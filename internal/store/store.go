// Package store persists events and the agent's own decisions.
//
// Events go into one JSON-lines file per UTC day, which makes retention a
// matter of deleting old files and keeps the format greppable with standard
// tools. State that must be read back (allowlist, bans, mute) lives in a small
// JSON file written atomically. The API is deliberately narrow so a SQLite
// backend can replace the implementation without touching callers.
package store

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/exception"
	"github.com/RsNest/auditdsec/internal/incident"
	"github.com/RsNest/auditdsec/internal/model"
)

const (
	eventsDirName = "events"
	stateFileName = "state.json"
	dayLayout     = "2006-01-02"
)

// AllowEntry is an address, or a CIDR network, that must never be banned. IP
// holds its canonical text.
type AllowEntry struct {
	IP      string    `json:"ip"`
	AddedAt time.Time `json:"added_at"`
	Note    string    `json:"note,omitempty"`
}

// Ban is a ban decision. A zero Until means permanent. Count carries how many
// times this address has been banned, which the escalation logic in v0.2 uses
// to decide between an hour, a day and forever.
type Ban struct {
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
	Until     time.Time `json:"until,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Count     int       `json:"count"`
	// Applied is kept for older readers: it is true exactly when State is
	// "applied".
	Applied bool `json:"applied"`

	// What the decision wants is implied by the record itself: while it is
	// active the address should be blocked. The fields below are what was
	// last observed of the enforcement. They never say "blocked" for a
	// backend that blocks nothing.
	State      string    `json:"state,omitempty"` // StatePending ... StateExpired
	Backend    string    `json:"backend,omitempty"`
	VerifiedAt time.Time `json:"verified_at,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	Attempts   int       `json:"attempts,omitempty"`
	Origin     string    `json:"origin,omitempty"` // detector, telegram, panel

	// NoticeDue is set in the same write that records an automatic decision
	// and cleared once its notification is in the outbox, so a crash between
	// the two cannot lose the notice.
	NoticeDue bool `json:"notice_due,omitempty"`
}

// Permanent reports whether the ban has no expiry.
func (b Ban) Permanent() bool { return b.Until.IsZero() }

// Active reports whether the ban is still in force at t.
func (b Ban) Active(t time.Time) bool { return b.Permanent() || t.Before(b.Until) }

type persisted struct {
	Allowlist map[string]AllowEntry `json:"allowlist"`
	Bans      map[string]Ban        `json:"bans"`
	// Releases are addresses whose block must be lifted: the owner asked for
	// it (unban, allow) and the firewall has not confirmed yet.
	Releases   map[string]Release `json:"releases,omitempty"`
	MutedUntil time.Time          `json:"muted_until,omitempty"`
	Meta       map[string]string  `json:"meta,omitempty"`
	// Detect is the durable progress of detection over the event journal.
	Detect *DetectState `json:"detect,omitempty"`
	// Incidents are the correlated stories built from consumed events.
	Incidents *incident.State `json:"incidents,omitempty"`
	// Exceptions are the owner's targeted silences; ExceptionSeq numbers them.
	Exceptions   []exception.Rule `json:"exceptions,omitempty"`
	ExceptionSeq int              `json:"exception_seq,omitempty"`
}

// Options configures a Store.
type Options struct {
	// Dir is the state directory, created if missing.
	Dir string
	// MaxRecent is how many events are kept in memory for /last.
	MaxRecent int
	// RetentionDays is how long event files are kept. Zero keeps them forever.
	RetentionDays int
	// Now is overridable for tests.
	Now func() time.Time
	// BeforeStateWrite, when set, runs before every write of the state file and
	// may fail it. It exists for tests that inject persistence failures.
	BeforeStateWrite func() error
}

// Store is the on-disk store. All methods are safe for concurrent use.
type Store struct {
	dir       string
	maxRecent int
	retention int
	now       func() time.Time

	mu         sync.Mutex
	day        string
	f          *os.File
	state      persisted
	recent     []model.Event
	indexes    map[string]*eventIndex
	indexOrder []string
	writeErr   error
	pending    map[string]bool          // journal days with input the detector has not consumed
	detecting  bool                     // a consumer is running in this process
	hits       map[string]ExceptionHits // exception hit counts since start
	hook       func() error             // test seam: runs before every state write
}

// Open prepares the store, creating the directory layout and loading state.
func Open(o Options) (*Store, error) {
	if o.Dir == "" {
		return nil, fmt.Errorf("store: Dir is required")
	}
	if o.MaxRecent <= 0 {
		o.MaxRecent = 200
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &Store{
		dir:       o.Dir,
		maxRecent: o.MaxRecent,
		retention: o.RetentionDays,
		now:       o.Now,
		hook:      o.BeforeStateWrite,
		indexes:   map[string]*eventIndex{},
		state: persisted{
			Allowlist: map[string]AllowEntry{},
			Bans:      map[string]Ban{},
			Releases:  map[string]Release{},
			Meta:      map[string]string{},
		},
	}
	if err := os.MkdirAll(filepath.Join(o.Dir, eventsDirName), 0o750); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", o.Dir, err)
	}
	if err := s.loadState(); err != nil {
		return nil, err
	}
	s.loadRecent()
	return s, nil
}

// Close flushes and closes the event file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// AppendEvent records an event and keeps it in the in-memory recent list.
func (s *Store) AppendEvent(ev model.Event) error {
	_, err := s.AppendEventOnce(ev)
	return err
}

// AppendEventOnce durably records an event, returning false for a stored ID.
// Legacy events without an ID remain append-only.
func (s *Store) AppendEventOnce(ev model.Event) (bool, error) {
	commit, err := s.AppendEventWithPlan(ev, nil)
	return commit.Added, err
}

type JournalCommit struct {
	Added    bool
	Position delivery.Position
}
type journalRecord struct {
	model.Event
	Plan *delivery.Plan `json:"notification_plan,omitempty"`
}

// AppendEventWithPlan makes the event and its notification policy one durable record.
func (s *Store) AppendEventWithPlan(ev model.Event, plan *delivery.Plan) (JournalCommit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return JournalCommit{}, s.writeErr
	}
	if ev.Time.IsZero() {
		ev.Time = s.now()
	}
	f, err := s.fileFor(ev.Time)
	if err != nil {
		return JournalCommit{}, err
	}
	var index *eventIndex
	if ev.ID != "" {
		if len(ev.ID) > 128 {
			return JournalCommit{}, fmt.Errorf("store: event ID is too long")
		}
		index, err = s.indexFor(ev.Time.UTC().Format(dayLayout))
		if err != nil {
			return JournalCommit{}, err
		}
		seen, err := s.containsEvent(index, ev.Time.UTC().Format(dayLayout), ev.ID)
		if err != nil {
			return JournalCommit{}, err
		}
		if !seen && legacyKey(ev) != "" {
			seen, err = s.containsEvent(index, ev.Time.UTC().Format(dayLayout), legacyKey(ev))
			if err != nil {
				return JournalCommit{}, err
			}
		}
		if seen {
			if err := f.Sync(); err != nil {
				s.writeErr = err
				return JournalCommit{}, err
			}
			return JournalCommit{}, nil
		}
	}
	b, err := json.Marshal(journalRecord{Event: ev, Plan: plan})
	if err != nil {
		return JournalCommit{}, fmt.Errorf("store: encode event: %w", err)
	}
	if len(b)+1 > maxJournalLine {
		return JournalCommit{}, fmt.Errorf("store: encoded event exceeds journal record limit")
	}
	start, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return JournalCommit{}, err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		s.writeErr = fmt.Errorf("store: write event: %w", err)
		return JournalCommit{}, s.writeErr
	}
	if err := f.Sync(); err != nil {
		s.writeErr = fmt.Errorf("store: sync event: %w", err)
		return JournalCommit{}, s.writeErr
	}
	if index != nil {
		index.add(ev.ID)
	} else if cached := s.indexes[ev.Time.UTC().Format(dayLayout)]; cached != nil {
		cached.add(legacyKey(ev))
	}
	s.recent = append(s.recent, ev)
	if len(s.recent) > s.maxRecent {
		s.recent = s.recent[len(s.recent)-s.maxRecent:]
	}
	s.noteAppendLocked(ev.Time.UTC().Format(dayLayout))
	return JournalCommit{Added: true, Position: delivery.Position{Day: ev.Time.UTC().Format(dayLayout), Start: start, End: start + int64(len(b)+1)}}, nil
}

// Recent returns up to n of the most recent events, newest last.
func (s *Store) Recent(n int) []model.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n <= 0 || n > len(s.recent) {
		n = len(s.recent)
	}
	out := make([]model.Event, n)
	copy(out, s.recent[len(s.recent)-n:])
	return out
}

// Stats summarizes the events written within the window ending now.
type Stats struct {
	Total    int
	Critical int
	Last     time.Time
	ByKind   map[model.Kind]int
}

// Stats counts events over a window by reading the day files it spans.
func (s *Store) Stats(window time.Duration) (Stats, error) {
	now := s.now().UTC()
	from := now.Add(-window)
	out := Stats{ByKind: map[model.Kind]int{}}

	for d := from.Truncate(24 * time.Hour); !d.After(now); d = d.Add(24 * time.Hour) {
		evs, err := s.readDay(d.Format(dayLayout))
		if err != nil {
			return out, err
		}
		for _, ev := range evs {
			if ev.Time.Before(from) {
				continue
			}
			out.Total++
			out.ByKind[ev.Kind]++
			if ev.Severity == model.SevCritical {
				out.Critical++
			}
			if ev.Time.After(out.Last) {
				out.Last = ev.Time
			}
		}
	}
	return out, nil
}

// Mute silences non-critical alerts until the given time.
func (s *Store) Mute(until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.MutedUntil = until
	return s.saveStateLocked()
}

// MutedUntil returns the mute deadline, zero if alerts are not muted.
func (s *Store) MutedUntil() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.MutedUntil.IsZero() || !s.state.MutedUntil.After(s.now()) {
		return time.Time{}
	}
	return s.state.MutedUntil
}

// SetMeta stores a small named value, such as the Telegram update offset.
func (s *Store) SetMeta(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Meta == nil {
		s.state.Meta = map[string]string{}
	}
	s.state.Meta[key] = value
	return s.saveStateLocked()
}

// GetMeta reads a named value.
func (s *Store) GetMeta(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Meta[key]
}

// Purge deletes event files older than the retention period and returns how
// many were removed.
func (s *Store) Purge() (int, error) {
	if s.retention <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := s.now().UTC().AddDate(0, 0, -s.retention).Format(dayLayout)
	dir := filepath.Join(s.dir, eventsDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("store: read %s: %w", dir, err)
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(name, ".jsonl")
		if day >= cutoff {
			continue
		}
		if day == s.day {
			continue
		}
		// Evidence the detector has not consumed yet is never deleted: the
		// decision it owes would be lost with the file.
		if s.detecting && s.state.Detect != nil {
			if fi, err := e.Info(); err == nil && fi.Size() > s.state.Detect.Cursors[day] {
				continue
			}
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return removed, fmt.Errorf("store: remove %s: %w", name, err)
		}
		removed++
		delete(s.indexes, day)
		if s.state.Detect != nil {
			delete(s.state.Detect.Cursors, day)
			delete(s.pending, day)
		}
	}
	return removed, nil
}

// fileFor returns the open event file for the event's day, rolling over at
// midnight UTC. The caller must hold the mutex.
func (s *Store) fileFor(t time.Time) (*os.File, error) {
	day := t.UTC().Format(dayLayout)
	if s.f != nil && s.day == day {
		return s.f, nil
	}
	if s.f != nil {
		s.f.Close()
		s.f = nil
	}
	path := filepath.Join(s.dir, eventsDirName, day+".jsonl")
	// A Windows append-only handle cannot truncate a torn tail. The store
	// mutex serializes this writer; seek to EOF after repairing the journal.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := repairJournalTail(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	s.f, s.day = f, day
	return f, nil
}

func (s *Store) readDay(day string) ([]model.Event, error) {
	var out []model.Event
	err := s.walkDay(day, func(ev model.Event) bool { out = append(out, ev); return true })
	return out, err
}

func (s *Store) loadState() error {
	path := filepath.Join(s.dir, stateFileName)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("store: read %s: %w", path, err)
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("store: parse %s: %w", path, err)
	}
	if p.Allowlist == nil {
		p.Allowlist = map[string]AllowEntry{}
	}
	if p.Bans == nil {
		p.Bans = map[string]Ban{}
	}
	if p.Meta == nil {
		p.Meta = map[string]string{}
	}
	s.state = p
	s.canonicalizeLocked()
	return nil
}

// loadRecent refills the in-memory list after a restart, so /last works
// immediately instead of after the next event.
func (s *Store) loadRecent() {
	now := s.now().UTC()
	var all []model.Event
	for _, d := range []time.Time{now.AddDate(0, 0, -1), now} {
		evs, err := s.readDay(d.Format(dayLayout))
		if err != nil {
			continue
		}
		all = append(all, evs...)
	}
	if len(all) > s.maxRecent {
		all = all[len(all)-s.maxRecent:]
	}
	s.recent = all
}

func (s *Store) saveStateLocked() error {
	if s.hook != nil {
		if err := s.hook(); err != nil {
			return fmt.Errorf("store: write state: %w", err)
		}
	}
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode state: %w", err)
	}
	path := filepath.Join(s.dir, stateFileName)
	if err := writeFileAtomic(path, b, 0o640); err != nil {
		return fmt.Errorf("store: write state: %w", err)
	}
	return nil
}

// maxScanDays bounds how far back Scan walks when no start is given.
const maxScanDays = 120

// WalkEvents streams committed records over a bounded date range without
// loading whole day files. Ordering within each day is append order; callers
// that aggregate by IP must compare timestamps rather than assume chronology.
func (s *Store) WalkEvents(from, to time.Time, fn func(model.Event) bool) error {
	now := s.now().UTC()
	if to.IsZero() || to.After(now) {
		to = now
	}
	if from.IsZero() || from.Before(to.AddDate(0, 0, -maxScanDays)) {
		from = to.AddDate(0, 0, -maxScanDays)
	}
	stopped := false
	for d := to.UTC().Truncate(24 * time.Hour); !d.Before(from.UTC().Truncate(24 * time.Hour)); d = d.AddDate(0, 0, -1) {
		err := s.walkDay(d.Format(dayLayout), func(ev model.Event) bool {
			if !ev.Time.After(from) || ev.Time.After(to) {
				return true
			}
			if !fn(ev) {
				stopped = true
				return false
			}
			return true
		})
		if err != nil || stopped {
			return err
		}
	}
	return nil
}

// Scan walks stored events newest first, between from and to (zero values mean
// "as far as retention goes" and "now"). Each event comes with an id of the
// form "YYYY-MM-DD:NNNNNN" that sorts in storage order, so a caller can resume
// below a given id. fn returns false to stop.
func (s *Store) Scan(from, to time.Time, fn func(id string, ev model.Event) bool) error {
	now := s.now().UTC()
	if to.IsZero() || to.After(now) {
		to = now
	}
	if from.IsZero() {
		from = to.AddDate(0, 0, -maxScanDays)
	}
	for d := to.UTC().Truncate(24 * time.Hour); !d.Before(from.UTC().Truncate(24 * time.Hour)); d = d.AddDate(0, 0, -1) {
		day := d.Format(dayLayout)
		evs, err := s.readDay(day)
		if err != nil {
			return err
		}
		for i := len(evs) - 1; i >= 0; i-- {
			ev := evs[i]
			if ev.Time.Before(from) || ev.Time.After(to) {
				continue
			}
			if !fn(fmt.Sprintf("%s:%06d", day, i), ev) {
				return nil
			}
		}
	}
	return nil
}
