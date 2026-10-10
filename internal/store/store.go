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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
)

const (
	eventsDirName = "events"
	stateFileName = "state.json"
	dayLayout     = "2006-01-02"
)

// AllowEntry is an address that must never be banned.
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
	Applied   bool      `json:"applied"`
}

// Permanent reports whether the ban has no expiry.
func (b Ban) Permanent() bool { return b.Until.IsZero() }

// Active reports whether the ban is still in force at t.
func (b Ban) Active(t time.Time) bool { return b.Permanent() || t.Before(b.Until) }

type persisted struct {
	Allowlist  map[string]AllowEntry `json:"allowlist"`
	Bans       map[string]Ban        `json:"bans"`
	MutedUntil time.Time             `json:"muted_until,omitempty"`
	Meta       map[string]string     `json:"meta,omitempty"`
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
		indexes:   map[string]*eventIndex{},
		state: persisted{
			Allowlist: map[string]AllowEntry{},
			Bans:      map[string]Ban{},
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return false, s.writeErr
	}
	if ev.Time.IsZero() {
		ev.Time = s.now()
	}
	f, err := s.fileFor(ev.Time)
	if err != nil {
		return false, err
	}
	var index *eventIndex
	if ev.ID != "" {
		if len(ev.ID) > 128 {
			return false, fmt.Errorf("store: event ID is too long")
		}
		index, err = s.indexFor(ev.Time.UTC().Format(dayLayout))
		if err != nil {
			return false, err
		}
		seen, err := s.containsEvent(index, ev.Time.UTC().Format(dayLayout), ev.ID)
		if err != nil {
			return false, err
		}
		if seen {
			if err := f.Sync(); err != nil {
				s.writeErr = err
				return false, err
			}
			return false, nil
		}
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return false, fmt.Errorf("store: encode event: %w", err)
	}
	if len(b)+1 > maxJournalLine {
		return false, fmt.Errorf("store: encoded event exceeds journal record limit")
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		s.writeErr = fmt.Errorf("store: write event: %w", err)
		return false, s.writeErr
	}
	if err := f.Sync(); err != nil {
		s.writeErr = fmt.Errorf("store: sync event: %w", err)
		return false, s.writeErr
	}
	if index != nil {
		index.add(ev.ID)
	}
	s.recent = append(s.recent, ev)
	if len(s.recent) > s.maxRecent {
		s.recent = s.recent[len(s.recent)-s.maxRecent:]
	}
	return true, nil
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

// Allow adds an address to the allowlist, so it can never be banned. This is
// what the "that was me" button does, and what protects an owner on a dynamic
// address from locking themselves out.
func (s *Store) Allow(ip, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Allowlist[ip] = AllowEntry{IP: ip, AddedAt: s.now(), Note: note}
	delete(s.state.Bans, ip)
	return s.saveStateLocked()
}

// IsAllowed reports whether the address is allowlisted.
func (s *Store) IsAllowed(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.state.Allowlist[ip]
	return ok
}

// Unallow removes an address from the allowlist, reporting whether it was there.
func (s *Store) Unallow(ip string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Allowlist[ip]; !ok {
		return false, nil
	}
	delete(s.state.Allowlist, ip)
	return true, s.saveStateLocked()
}

// Allowlist returns the allowlist, sorted by address.
func (s *Store) Allowlist() []AllowEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AllowEntry, 0, len(s.state.Allowlist))
	for _, e := range s.state.Allowlist {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// ErrAllowlisted is returned when a ban is refused because the address is
// allowlisted. Refusing here, in the store, means no caller can bypass it.
var ErrAllowlisted = fmt.Errorf("store: address is allowlisted")

// RecordBan stores a ban decision, incrementing the repeat counter for an
// address that has been banned before.
func (s *Store) RecordBan(ip, reason string, until time.Time) (Ban, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Allowlist[ip]; ok {
		return Ban{}, ErrAllowlisted
	}
	b := s.state.Bans[ip]
	b.IP = ip
	b.CreatedAt = s.now()
	b.Until = until
	b.Reason = reason
	b.Count++
	s.state.Bans[ip] = b
	return b, s.saveStateLocked()
}

// MarkBanApplied records that a Banner actually enforced the decision on the
// host, which v0.1 never does and v0.2 will.
func (s *Store) MarkBanApplied(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.state.Bans[ip]
	if !ok {
		return nil
	}
	b.Applied = true
	s.state.Bans[ip] = b
	return s.saveStateLocked()
}

// Bans returns every recorded ban, newest first.
func (s *Store) Bans() []Ban {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Ban, 0, len(s.state.Bans))
	for _, b := range s.state.Bans {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Unban removes a ban decision, reporting whether it existed.
func (s *Store) Unban(ip string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Bans[ip]; !ok {
		return false, nil
	}
	delete(s.state.Bans, ip)
	return true, s.saveStateLocked()
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
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return removed, fmt.Errorf("store: remove %s: %w", name, err)
		}
		removed++
		delete(s.indexes, day)
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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := repairJournalTail(f); err != nil {
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
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode state: %w", err)
	}
	path := filepath.Join(s.dir, stateFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return fmt.Errorf("store: write state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("store: replace state: %w", err)
	}
	return nil
}

// maxScanDays bounds how far back Scan walks when no start is given.
const maxScanDays = 120

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
