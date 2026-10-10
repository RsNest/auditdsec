package store

import (
	"errors"
	"sort"

	"github.com/RsNest/auditdsec/internal/incident"
)

// ErrNoIncident: no incident has that ID, or it is already in that state.
var ErrNoIncident = errors.New("store: no such incident, or no change")

func (s *Store) incidentsLocked() *incident.State {
	if s.state.Incidents == nil {
		s.state.Incidents = &incident.State{}
	}
	if s.state.Incidents.Items == nil {
		s.state.Incidents.Items = map[string]*incident.Incident{}
	}
	return s.state.Incidents
}

func (s *Store) applyIncidentsLocked(ch incident.Change) {
	st := s.incidentsLocked()
	for _, u := range ch.Upsert {
		st.Items[u.ID] = u
	}
	for _, id := range ch.Drop {
		delete(st.Items, id)
	}
	st.Seq = ch.Seq
}

// Incidents returns copies of the incidents, most recently active first.
// state "" returns all; "open" returns new and acknowledged ones.
func (s *Store) Incidents(state string) []incident.Incident {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []incident.Incident
	if s.state.Incidents == nil {
		return out
	}
	for _, in := range s.state.Incidents.Items {
		switch {
		case state == "" || state == in.State:
		case state == "open" && in.State != incident.Resolved:
		default:
			continue
		}
		out = append(out, *in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// Incident returns one incident.
func (s *Store) Incident(id string) (incident.Incident, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Incidents == nil {
		return incident.Incident{}, false
	}
	in, ok := s.state.Incidents.Items[id]
	if !ok {
		return incident.Incident{}, false
	}
	return *in, true
}

// SetIncidentState moves an incident to new, acknowledged or resolved and
// records who did it. The write is all or nothing.
func (s *Store) SetIncidentState(id, state, actor string) (incident.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.incidentsLocked()
	cur, ok := st.Items[id]
	if !ok {
		return incident.Incident{}, ErrNoIncident
	}
	next, changed := incident.SetState(cur, state, actor, s.now())
	if !changed {
		return *cur, ErrNoIncident
	}
	st.Items[id] = next
	if err := s.saveStateLocked(); err != nil {
		st.Items[id] = cur
		return *cur, err
	}
	return *next, nil
}
