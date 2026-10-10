// Package incident turns a stream of separate events into a story: one record
// per related run of activity, with the reason it was raised, how serious it
// got, and whether a person has dealt with it.
//
// Correlation is deliberately conservative and deterministic. Two events are
// related only through one of these links:
//
//   - the same directly observed source address (ssh logins, the ban of that
//     address);
//   - an action whose SSH session was attributed to that address with
//     confidence "observed" (see internal/session) — never "correlated" or
//     "unknown", never a shared user name, never closeness in time alone;
//   - the same audit session (session ID and login uid) when its address is
//     unknown;
//   - the same host-level condition (log tampering, audit health).
//
// The package is pure: it computes which incidents change, and the store
// applies that change in the same atomic write as the detection cursor, so a
// replayed event never counts twice.
package incident

import (
	"sort"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
)

// States of an incident.
const (
	New          = "new"
	Acknowledged = "acknowledged"
	Resolved     = "resolved"
)

// Bounds. They keep the state file small however noisy the host is.
const (
	MaxIncidents = 500
	MaxEvents    = 40 // most recent event references per incident
	MaxNotes     = 20
	// ResolvedKeep is how long a resolved incident is kept before it is dropped.
	ResolvedKeep = 90 * 24 * time.Hour
	// IPGap/SessionGap/HostGap: silence after which new activity is a new story.
	IPGap      = time.Hour
	SessionGap = 24 * time.Hour
	HostGap    = 6 * time.Hour
)

// Ref is a small reference to an event that belongs to an incident.
type Ref struct {
	ID       string         `json:"id"`
	Time     time.Time      `json:"time"`
	Kind     model.Kind     `json:"kind"`
	Severity model.Severity `json:"severity"`
	User     string         `json:"user,omitempty"`
	// Via says how the event was linked: "address", "session" or "host".
	Via string `json:"via,omitempty"`
}

// Note is one operator action or system remark on an incident.
type Note struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
}

// Incident is one related run of activity.
type Incident struct {
	ID         string            `json:"id"`
	Key        string            `json:"key"`
	State      string            `json:"state"`
	Opened     time.Time         `json:"opened"`
	LastSeen   time.Time         `json:"last_seen"`
	Severity   model.Severity    `json:"severity"`
	AckedAt    model.Severity    `json:"acked_severity,omitempty"`
	ReasonKey  string            `json:"reason_key"`
	ReasonArgs map[string]string `json:"reason_args,omitempty"`
	// SrcIP is the observed address the incident is about, when it has one.
	SrcIP    string         `json:"src_ip,omitempty"`
	Kinds    map[string]int `json:"kinds,omitempty"`
	Total    int            `json:"total"`
	Events   []Ref          `json:"events,omitempty"`
	Bans     []string       `json:"bans,omitempty"`
	Notes    []Note         `json:"notes,omitempty"`
	Resolved time.Time      `json:"resolved_at,omitempty"`
}

// State is every incident, as stored.
type State struct {
	Seq   int                  `json:"seq"`
	Items map[string]*Incident `json:"items,omitempty"`
}

// Input is what the correlator sees of one consumed event.
type Input struct {
	Event model.Event
	// Banned lists addresses a new ban decision was recorded for by this event.
	Banned []Ban
}

// Ban is a decision created while consuming the event.
type Ban struct{ IP, Reason string }

// opener kinds raise an incident by themselves.
var opener = map[model.Kind]bool{
	model.KindLogTamper: true, model.KindAuthorizedKeysChange: true, model.KindSuspiciousExec: true,
	model.KindPersistence: true, model.KindUserChange: true, model.KindConfigChange: true,
	model.KindAuditdStopped: true, model.KindLoginAfterBruteForce: true,
}

func opens(ev model.Event) bool {
	if ev.Severity == model.SevCritical {
		return true
	}
	return ev.Severity >= model.SevWarn && opener[ev.Kind]
}

// link decides which key an event belongs to, and how.
type link struct {
	key, via, ip string
	gap          time.Duration
}

func linkOf(ev model.Event) (link, bool) {
	if c := ev.Context; c != nil && c.Session != nil && c.Session.Confidence == model.ConfObserved && c.Session.Addr != "" {
		return link{key: "ip:" + c.Session.Addr, via: "session", ip: c.Session.Addr, gap: IPGap}, true
	}
	switch ev.Kind {
	case model.KindSSHLoginFail, model.KindSSHLoginOK, model.KindLoginAfterBruteForce:
		if ev.SrcIP != "" {
			return link{key: "ip:" + ev.SrcIP, via: "address", ip: ev.SrcIP, gap: IPGap}, true
		}
	}
	if c := ev.Context; c != nil && c.SessionID != "" && c.LoginUID != "" {
		return link{key: "ses:" + c.SessionID + ":" + c.LoginUID, via: "session", gap: SessionGap}, true
	}
	switch ev.Kind {
	case model.KindLogTamper, model.KindAuditdStopped, model.KindPersistence, model.KindAuthorizedKeysChange,
		model.KindSuspiciousExec, model.KindUserChange, model.KindConfigChange:
		return link{key: "host:" + string(ev.Kind), via: "host", gap: HostGap}, true
	}
	return link{}, false
}

func reasonOf(ev model.Event, l link) (string, map[string]string) {
	args := map[string]string{"ip": l.ip, "kind": string(ev.Kind), "user": ev.User}
	switch {
	case ev.Kind == model.KindLoginAfterBruteForce:
		return "incident.reason.login_after_bruteforce", args
	case l.via == "session" && l.ip != "":
		return "incident.reason.action_in_session", args
	case ev.Kind == model.KindAuditdStopped:
		return "incident.reason.audit", args
	default:
		return "incident.reason.action", args
	}
}

func openIncident(st *State, key string) *Incident {
	var best *Incident
	for _, in := range st.Items {
		if in.Key == key && in.State != Resolved && (best == nil || in.LastSeen.After(best.LastSeen)) {
			best = in
		}
	}
	return best
}

func clone(in *Incident) *Incident {
	c := *in
	c.Events = append([]Ref(nil), in.Events...)
	c.Bans = append([]string(nil), in.Bans...)
	c.Notes = append([]Note(nil), in.Notes...)
	c.Kinds = make(map[string]int, len(in.Kinds))
	for k, v := range in.Kinds {
		c.Kinds[k] = v
	}
	if in.ReasonArgs != nil {
		c.ReasonArgs = make(map[string]string, len(in.ReasonArgs))
		for k, v := range in.ReasonArgs {
			c.ReasonArgs[k] = v
		}
	}
	return &c
}

// Change is the outcome of correlating one event: the incidents to write, and
// the ones to drop to stay inside the bounds.
type Change struct {
	Upsert []*Incident
	Drop   []string
	Seq    int
}

// Plan computes how consuming one event changes the incidents. It does not
// modify st. Applying the same event twice changes nothing the second time.
func Plan(st *State, in Input) Change {
	ch := Change{Seq: st.Seq}
	ev := in.Event
	touched := map[string]*Incident{}
	get := func(key string, gap time.Duration, at time.Time) *Incident {
		if t, ok := touched[key]; ok {
			return t
		}
		cur := openIncident(st, key)
		if cur == nil || at.Sub(cur.LastSeen) > gap {
			return nil
		}
		c := clone(cur)
		touched[key] = c
		return c
	}
	create := func(l link, ev model.Event, reasonKey string, args map[string]string) *Incident {
		ch.Seq++
		n := &Incident{
			ID: "inc-" + itoa(ch.Seq), Key: l.key, State: New, Opened: ev.Time, LastSeen: ev.Time,
			ReasonKey: reasonKey, ReasonArgs: args, SrcIP: l.ip, Kinds: map[string]int{},
		}
		touched[l.key] = n
		return n
	}
	attach := func(n *Incident, ev model.Event, via string) {
		for _, r := range n.Events {
			if r.ID != "" && r.ID == ev.ID {
				return // the same event again
			}
		}
		if ev.Time.After(n.LastSeen) {
			n.LastSeen = ev.Time
		}
		n.Total++
		n.Kinds[string(ev.Kind)]++
		n.Events = append(n.Events, Ref{ID: ev.ID, Time: ev.Time, Kind: ev.Kind, Severity: ev.Severity, User: ev.User, Via: via})
		if len(n.Events) > MaxEvents {
			n.Events = n.Events[len(n.Events)-MaxEvents:]
		}
		if ev.Severity > n.Severity {
			n.Severity = ev.Severity
		}
		// More serious than what a person acknowledged: it needs eyes again.
		if n.State == Acknowledged && n.Severity > n.AckedAt {
			n.State = New
			addNote(n, ev.Time, "system", "escalated")
		}
	}

	// A ban decision opens (or joins) the incident of its address.
	for _, b := range in.Banned {
		l := link{key: "ip:" + b.IP, via: "address", ip: b.IP, gap: IPGap}
		n := get(l.key, l.gap, ev.Time)
		if n == nil {
			n = create(l, ev, "incident.reason.bruteforce_ban", map[string]string{"ip": b.IP, "detail": b.Reason})
		}
		if !contains(n.Bans, b.IP) {
			n.Bans = append(n.Bans, b.IP)
		}
		if n.Severity < model.SevWarn {
			n.Severity = model.SevWarn
		}
	}

	if l, ok := linkOf(ev); ok && ev.Suppressed == "" {
		n := get(l.key, l.gap, ev.Time)
		if n == nil && opens(ev) {
			rk, args := reasonOf(ev, l)
			n = create(l, ev, rk, args)
		}
		if n != nil {
			attach(n, ev, l.via)
		}
	}

	for _, n := range touched {
		ch.Upsert = append(ch.Upsert, n)
	}
	sort.Slice(ch.Upsert, func(i, j int) bool { return ch.Upsert[i].ID < ch.Upsert[j].ID })
	ch.Drop = overflow(st, ch.Upsert, ev.Time)
	return ch
}

// overflow returns the incidents to drop so the set stays bounded: expired
// resolved ones first, then the oldest resolved, then the least recently seen.
func overflow(st *State, upsert []*Incident, now time.Time) []string {
	keep := map[string]*Incident{}
	for id, in := range st.Items {
		keep[id] = in
	}
	for _, in := range upsert {
		keep[in.ID] = in
	}
	var drop []string
	for id, in := range keep {
		if in.State == Resolved && now.Sub(in.Resolved) > ResolvedKeep {
			drop = append(drop, id)
			delete(keep, id)
		}
	}
	for len(keep) > MaxIncidents {
		var victim *Incident
		for _, in := range keep {
			if victim == nil || rank(in) < rank(victim) || (rank(in) == rank(victim) && in.LastSeen.Before(victim.LastSeen)) {
				victim = in
			}
		}
		drop = append(drop, victim.ID)
		delete(keep, victim.ID)
	}
	sort.Strings(drop)
	return drop
}

func rank(in *Incident) int {
	if in.State == Resolved {
		return 0
	}
	return 1
}

// SetState returns the incident after an operator action, or false when the
// transition does not apply (unknown ID, already in that state).
func SetState(in *Incident, state, actor string, at time.Time) (*Incident, bool) {
	if in == nil || in.State == state {
		return nil, false
	}
	c := clone(in)
	c.State = state
	switch state {
	case Acknowledged:
		c.AckedAt = c.Severity
	case Resolved:
		c.Resolved = at
	case New:
		c.Resolved = time.Time{}
	}
	addNote(c, at, actor, state)
	return c, true
}

func addNote(n *Incident, at time.Time, actor, action string) {
	n.Notes = append(n.Notes, Note{At: at, Actor: actor, Action: action})
	if len(n.Notes) > MaxNotes {
		n.Notes = n.Notes[len(n.Notes)-MaxNotes:]
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
