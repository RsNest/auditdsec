package parse

import (
	"strings"
	"time"
)

// Event is every record auditd wrote for one audit serial. A single user
// action such as "vim /etc/passwd" produces a SYSCALL record, one or more PATH
// records and a terminating EOE record, all sharing the serial.
type Event struct {
	Time    time.Time
	Serial  int64
	Node    string // node= of a log collected from several hosts; usually empty
	Records []Record

	// Complete is true when the event ended normally (its EOE record, or a
	// record type that is an event on its own). Otherwise IncompleteReason
	// says why it was closed early.
	Complete         bool
	IncompleteReason string

	// Start is the source offset of the event's first line, or -1.
	Start int64
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

// Why an event was closed without its end-of-event record. An incomplete
// event is still reported, marked as such: a partial record is evidence, but
// not proof of everything that happened.
const (
	IncompleteTimeout  = "no end-of-event record arrived within the timeout"
	IncompletePending  = "too many audit events open at once; the oldest was closed early"
	IncompleteBytes    = "the open audit events exceeded the memory budget; the oldest was closed early"
	IncompleteRecords  = "the event had more records than the limit; the rest were dropped"
	IncompleteLate     = "records arrived after the event had already been closed"
	IncompleteShutdown = "the agent stopped before the event ended"
)

// Limits bound the memory the assembler may use. Exceeding one never loses
// data silently: the affected event is closed early and marked incomplete.
type Limits struct {
	MaxPending int // open events at once
	MaxRecords int // records kept for one event
	MaxBytes   int // raw bytes held across all open events
}

// DefaultLimits fit comfortably inside the agent's 64 MiB container.
var DefaultLimits = Limits{MaxPending: 1024, MaxRecords: 256, MaxBytes: 4 << 20}

// eventKey identifies one audit event. The serial alone is not unique: it
// restarts with the kernel, and a log may carry several hosts (node=).
type eventKey struct {
	node   string
	ms     int64
	serial int64
}

func keyOf(r Record) eventKey {
	return eventKey{node: r.Fields["node"], ms: r.Time.UnixMilli(), serial: r.Serial}
}

// Assembler groups records into events. Records of different events may be
// interleaved and arrive out of order, so any number of events are open at
// once. An event closes on its EOE record; a record type that is an event on
// its own (the user-space USER_*, CRED_*, DAEMON_* messages) closes at once;
// anything else closes after sitting idle for the timeout.
type Assembler struct {
	timeout time.Duration
	lim     Limits
	pending map[eventKey]*pendingEvent
	order   []eventKey // oldest first
	bytes   int

	// Recently closed events, so a record that arrives after its EOE is
	// recognised as late instead of quietly starting a fragment.
	closed     map[eventKey]struct{}
	closedRing []eventKey
	closedNext int
}

type pendingEvent struct {
	ev      *Event
	seen    time.Time
	bytes   int
	dropped int
	late    bool
}

const closedMemory = 4096

// NewAssembler returns an assembler with the default limits. A timeout of a
// second or two is plenty: the records of one event are written together.
func NewAssembler(timeout time.Duration) *Assembler {
	return NewAssemblerWithLimits(timeout, DefaultLimits)
}

// NewAssemblerWithLimits is NewAssembler with explicit memory limits.
func NewAssemblerWithLimits(timeout time.Duration, lim Limits) *Assembler {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if lim.MaxPending <= 0 {
		lim.MaxPending = DefaultLimits.MaxPending
	}
	if lim.MaxRecords <= 0 {
		lim.MaxRecords = DefaultLimits.MaxRecords
	}
	if lim.MaxBytes <= 0 {
		lim.MaxBytes = DefaultLimits.MaxBytes
	}
	return &Assembler{
		timeout: timeout, lim: lim,
		pending:    map[eventKey]*pendingEvent{},
		closed:     map[eventKey]struct{}{},
		closedRing: make([]eventKey, closedMemory),
	}
}

// standalone reports record types that are a whole event by themselves: the
// messages user space sends through the audit netlink socket. They never get
// an EOE record.
func standalone(typ string) bool {
	for _, p := range []string{"USER_", "CRED_", "DAEMON_", "ADD_", "DEL_", "GRP_", "ACCT_", "ROLE_", "SERVICE_", "SYSTEM_", "ANOM_LOGIN", "CHGRP_", "CHUSER_"} {
		if strings.HasPrefix(typ, p) {
			return true
		}
	}
	return typ == "LOGIN"
}

// Add feeds one log line and returns the events that became complete. Lines
// that carry no record yield ErrSkip, which callers normally ignore.
func (a *Assembler) Add(line string, now time.Time) ([]*Event, error) {
	return a.AddAt(line, -1, now)
}

// AddAt is Add for a line that starts at a known offset of the source. The
// assembler remembers the earliest offset of every open event, so the reader
// knows how far its position may safely be saved (OldestOpen).
func (a *Assembler) AddAt(line string, start int64, now time.Time) ([]*Event, error) {
	rec, err := ParseLine(line)
	if err != nil {
		return nil, err
	}
	k := keyOf(rec)

	if rec.Type == "EOE" {
		if _, ok := a.pending[k]; ok {
			return a.close(k, true, ""), nil
		}
		return nil, nil // the end of an event that was closed already
	}

	p, open := a.pending[k]
	if !open {
		_, wasClosed := a.closed[k]
		ev := &Event{Time: rec.Time, Serial: rec.Serial, Node: rec.Fields["node"], Start: start}
		if standalone(rec.Type) && !wasClosed {
			ev.Records = []Record{rec}
			ev.Complete = true
			a.remember(k)
			return []*Event{ev}, nil
		}
		p = &pendingEvent{ev: ev, late: wasClosed}
		a.pending[k] = p
		a.order = append(a.order, k)
	}
	p.seen = now
	if start >= 0 && (p.ev.Start < 0 || start < p.ev.Start) {
		p.ev.Start = start
	}
	if len(p.ev.Records) >= a.lim.MaxRecords {
		p.dropped++
	} else {
		p.ev.Records = append(p.ev.Records, rec)
		n := len(rec.Raw)
		p.bytes += n
		a.bytes += n
	}

	// Over a budget: close the oldest events (never the one just fed, unless
	// it alone is too big) until it fits.
	var done []*Event
	for len(a.pending) > a.lim.MaxPending || a.bytes > a.lim.MaxBytes {
		victim := a.order[0]
		if victim == k && len(a.order) > 1 {
			victim = a.order[1]
		}
		why := IncompletePending
		if a.bytes > a.lim.MaxBytes {
			why = IncompleteBytes
		}
		done = append(done, a.close(victim, false, why)...)
		if victim == k {
			break
		}
	}
	return done, nil
}

// Expire closes events that have been idle for longer than the timeout.
func (a *Assembler) Expire(now time.Time) []*Event {
	var done []*Event
	for _, k := range append([]eventKey(nil), a.order...) {
		if p, ok := a.pending[k]; ok && now.Sub(p.seen) >= a.timeout {
			done = append(done, a.close(k, false, IncompleteTimeout)...)
		}
	}
	return done
}

// Flush closes everything still open, for shutdown.
func (a *Assembler) Flush() []*Event {
	var done []*Event
	for _, k := range append([]eventKey(nil), a.order...) {
		done = append(done, a.close(k, false, IncompleteShutdown)...)
	}
	return done
}

// Pending reports how many events are still open, for diagnostics.
func (a *Assembler) Pending() int { return len(a.pending) }

// OldestOpen is the smallest source offset of a line that belongs to an
// event still open. A reader must not save its position past it: those lines
// are not stored anywhere yet and have to be read again after a crash.
func (a *Assembler) OldestOpen() (int64, bool) {
	best, ok := int64(0), false
	for _, p := range a.pending {
		if p.ev.Start >= 0 && (!ok || p.ev.Start < best) {
			best, ok = p.ev.Start, true
		}
	}
	return best, ok
}

// close removes an open event and returns it. ended says its EOE arrived;
// otherwise why is the reason it closed early. A single record that is not a
// syscall closing on the timeout is a whole event of its own (a kernel record
// with no EOE, such as CONFIG_CHANGE on older kernels), so it is complete.
func (a *Assembler) close(k eventKey, ended bool, why string) []*Event {
	p, ok := a.pending[k]
	if !ok {
		return nil
	}
	delete(a.pending, k)
	for i, o := range a.order {
		if o == k {
			a.order = append(a.order[:i], a.order[i+1:]...)
			break
		}
	}
	a.bytes -= p.bytes
	a.remember(k)
	ev := p.ev
	if len(ev.Records) == 0 {
		return nil
	}
	switch {
	case p.late:
		ev.Complete, ev.IncompleteReason = false, IncompleteLate
	case p.dropped > 0:
		ev.Complete, ev.IncompleteReason = false, IncompleteRecords
	case ended:
		ev.Complete = true
	case why == IncompleteTimeout && len(ev.Records) == 1 && ev.Records[0].Type != "SYSCALL":
		ev.Complete = true
	default:
		ev.Complete, ev.IncompleteReason = false, why
	}
	return []*Event{ev}
}

func (a *Assembler) remember(k eventKey) {
	old := a.closedRing[a.closedNext]
	if _, ok := a.closed[old]; ok && old != k {
		delete(a.closed, old)
	}
	a.closedRing[a.closedNext] = k
	a.closedNext = (a.closedNext + 1) % len(a.closedRing)
	a.closed[k] = struct{}{}
}

// TargetPath is the file a syscall event acted on. PATH records also list the
// directories the kernel walked (nametype=PARENT), so the last record is not
// necessarily the file: a created or deleted name wins, then a plain one. A
// relative name is resolved against the CWD record.
func (e *Event) TargetPath() string {
	rank := func(nt string) int {
		switch nt {
		case "CREATE":
			return 4
		case "DELETE":
			return 3
		case "NORMAL", "":
			return 2
		case "UNKNOWN":
			return 1
		}
		return 0 // PARENT
	}
	best, bestRank := "", 0
	for _, r := range e.Records {
		if r.Type != "PATH" {
			continue
		}
		n := r.Fields["name"]
		if n == "" || n == "(null)" {
			continue
		}
		if rk := rank(r.Fields["nametype"]); rk > bestRank || (rk == bestRank && rk > 0) {
			best, bestRank = n, rk
		}
	}
	if best == "" {
		return ""
	}
	if !strings.HasPrefix(best, "/") {
		if cwd := e.FieldOf("CWD", "cwd"); strings.HasPrefix(cwd, "/") {
			best = strings.TrimSuffix(cwd, "/") + "/" + strings.TrimPrefix(best, "./")
		}
	}
	return best
}
