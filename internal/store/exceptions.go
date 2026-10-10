package store

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/RsNest/auditdsec/internal/exception"
	"github.com/RsNest/auditdsec/internal/model"
)

// ErrNoException: no exception has that ID.
var ErrNoException = errors.New("store: no such exception")

// ExceptionHits is how often a rule silenced an event since the agent started.
// It is in memory on purpose: counting in the state file would turn every
// silenced event into a disk write.
type ExceptionHits struct {
	Count int
	Last  time.Time
}

// AddException validates and stores a new exception.
func (s *Store) AddException(r exception.Rule, actor string) (exception.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	r, err := exception.Validate(r, now)
	if err != nil {
		return exception.Rule{}, err
	}
	prev, prevSeq := s.state.Exceptions, s.state.ExceptionSeq
	keep := make([]exception.Rule, 0, len(prev)+1)
	for _, old := range prev {
		if now.Sub(old.ExpiresAt) <= exception.KeepExpiry {
			keep = append(keep, old)
		}
	}
	if len(keep) >= exception.MaxRules {
		return exception.Rule{}, fmt.Errorf("%w: at most %d exceptions", exception.ErrInvalid, exception.MaxRules)
	}
	s.state.ExceptionSeq++
	r.ID = fmt.Sprintf("exc-%d", s.state.ExceptionSeq)
	r.CreatedBy = actor
	s.state.Exceptions = append(keep, r)
	if err := s.saveStateLocked(); err != nil {
		s.state.Exceptions, s.state.ExceptionSeq = prev, prevSeq
		return exception.Rule{}, err
	}
	return r, nil
}

// RemoveException deletes an exception.
func (s *Store) RemoveException(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.state.Exceptions
	next := make([]exception.Rule, 0, len(prev))
	for _, r := range prev {
		if r.ID != id {
			next = append(next, r)
		}
	}
	if len(next) == len(prev) {
		return ErrNoException
	}
	s.state.Exceptions = next
	if err := s.saveStateLocked(); err != nil {
		s.state.Exceptions = prev
		return err
	}
	delete(s.hits, id)
	return nil
}

// Exceptions lists the rules, newest first, with their hit counts.
func (s *Store) Exceptions() ([]exception.Rule, map[string]ExceptionHits) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]exception.Rule(nil), s.state.Exceptions...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	hits := make(map[string]ExceptionHits, len(s.hits))
	for k, v := range s.hits {
		hits[k] = v
	}
	return out, hits
}

// MatchException returns the first active rule that silences the event and
// counts the hit.
func (s *Store) MatchException(ev model.Event) (exception.Rule, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, r := range s.state.Exceptions {
		if r.Matches(ev, now) {
			if s.hits == nil {
				s.hits = map[string]ExceptionHits{}
			}
			h := s.hits[r.ID]
			h.Count++
			h.Last = now
			s.hits[r.ID] = h
			return r, true
		}
	}
	return exception.Rule{}, false
}
