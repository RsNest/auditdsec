package parse

import (
	"errors"
	"strings"
	"time"
)

// Event is every record auditd wrote for one audit serial. A single user
// action such as "vim /etc/passwd" produces a SYSCALL record, one or more PATH
// records and a terminating EOE record, all sharing the serial.
type Event struct {
	Time    time.Time
	Serial  int64
	Records []Record
}

// Rec returns the first record of the given type.
func (e *Event) Rec(typ string) (Record, bool) {
	for _, r := range e.Records {
		if r.Type == typ {
			return r, true
		}
	}
	return Record{}, false
}

// Has reports whether a record of that type is present.
func (e *Event) Has(typ string) bool {
	_, ok := e.Rec(typ)
	return ok
}

// HasAny reports whether any of the types is present.
func (e *Event) HasAny(types ...string) bool {
	for _, t := range types {
		if e.Has(t) {
			return true
		}
	}
	return false
}

// Types lists the record types in order of appearance.
func (e *Event) Types() []string {
	out := make([]string, 0, len(e.Records))
	for _, r := range e.Records {
		out = append(out, r.Type)
	}
	return out
}

// Field returns the first non-empty value of key across all records.
func (e *Event) Field(key string) string {
	for _, r := range e.Records {
		if v := r.Fields[key]; v != "" {
			return v
		}
	}
	return ""
}

// FieldOf returns a field from the first record of a given type.
func (e *Event) FieldOf(typ, key string) string {
	if r, ok := e.Rec(typ); ok {
		return r.Fields[key]
	}
	return ""
}

// FirstField returns the first non-empty value among several candidate keys,
// which is how auditd's near-synonyms (addr/hostname, acct/id) are resolved.
func (e *Event) FirstField(keys ...string) string {
	for _, k := range keys {
		if v := e.Field(k); v != "" {
			return v
		}
	}
	return ""
}

// Paths returns the file names from the PATH records, de-duplicated.
func (e *Event) Paths() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range e.Records {
		if r.Type != "PATH" {
			continue
		}
		if n := r.Fields["name"]; n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// AuditKeys returns every `-k` rule name attached to the event.
func (e *Event) AuditKeys() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range e.Records {
		for _, k := range r.AuditKeys() {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

// Raw is the original log text of the whole event.
func (e *Event) Raw() string {
	lines := make([]string, 0, len(e.Records))
	for _, r := range e.Records {
		lines = append(lines, r.Raw)
	}
	return strings.Join(lines, "\n")
}

// Assembler groups records into events. auditd writes the records of one event
// contiguously, so an event is complete once a record with a different serial
// shows up, once its EOE record arrives, or once it has sat untouched for the
// assembler timeout (which is what finishes the last event in a quiet log).
type Assembler struct {
	timeout time.Duration
	pending map[int64]*pendingEvent
	order   []int64
}

type pendingEvent struct {
	ev   *Event
	seen time.Time
}

// NewAssembler returns an assembler. A timeout of a second or two is plenty:
// the records of one event are written in one go.
func NewAssembler(timeout time.Duration) *Assembler {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Assembler{timeout: timeout, pending: map[int64]*pendingEvent{}}
}

// Add feeds one log line and returns the events that became complete. Lines
// that carry no record yield ErrSkip, which callers normally ignore.
func (a *Assembler) Add(line string, now time.Time) ([]*Event, error) {
	rec, err := ParseLine(line)
	if err != nil {
		if errors.Is(err, ErrSkip) {
			return nil, err
		}
		return nil, err
	}

	if rec.Type == "EOE" {
		return a.take(rec.Serial), nil
	}

	p, ok := a.pending[rec.Serial]
	if !ok {
		p = &pendingEvent{ev: &Event{Time: rec.Time, Serial: rec.Serial}}
		a.pending[rec.Serial] = p
		a.order = append(a.order, rec.Serial)
	}
	p.ev.Records = append(p.ev.Records, rec)
	p.seen = now

	// Any other open event cannot receive more records.
	var done []*Event
	for _, serial := range append([]int64(nil), a.order...) {
		if serial == rec.Serial {
			continue
		}
		done = append(done, a.take(serial)...)
	}
	return done, nil
}

// Expire completes events that have been idle for longer than the timeout.
func (a *Assembler) Expire(now time.Time) []*Event {
	var done []*Event
	for _, serial := range append([]int64(nil), a.order...) {
		p, ok := a.pending[serial]
		if !ok {
			continue
		}
		if now.Sub(p.seen) >= a.timeout {
			done = append(done, a.take(serial)...)
		}
	}
	return done
}

// Flush completes everything still open, for shutdown.
func (a *Assembler) Flush() []*Event {
	var done []*Event
	for _, serial := range append([]int64(nil), a.order...) {
		done = append(done, a.take(serial)...)
	}
	return done
}

// Pending reports how many events are still open, for diagnostics.
func (a *Assembler) Pending() int { return len(a.pending) }

func (a *Assembler) take(serial int64) []*Event {
	p, ok := a.pending[serial]
	if !ok {
		return nil
	}
	delete(a.pending, serial)
	for i, s := range a.order {
		if s == serial {
			a.order = append(a.order[:i], a.order[i+1:]...)
			break
		}
	}
	if len(p.ev.Records) == 0 {
		return nil
	}
	return []*Event{p.ev}
}
