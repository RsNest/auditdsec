package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

const (
	maxSessions     = 16
	failWindow      = 10 * time.Minute
	failLimit       = 5
	maxTrackedAddrs = 4096
)

// Kinds of session. A setup session is what the bootstrap code and admin/admin
// buy: it can finish the first-time setup and nothing else.
const (
	kindFull  = "full"
	kindSetup = "setup"
)

type session struct {
	expires time.Time
	kind    string
	gen     int64 // bootstrap generation a setup session belongs to
}

// sessions holds bearer tokens in memory. Only the SHA-256 of a token is kept,
// so a memory dump does not hand out live sessions, and a restart signs
// everyone out, which is the right default for a security tool.
type sessions struct {
	mu  sync.Mutex
	ttl time.Duration
	now func() time.Time
	m   map[[32]byte]session
}

func newSessions(ttl time.Duration, now func() time.Time) *sessions {
	return &sessions{ttl: ttl, now: now, m: map[[32]byte]session{}}
}

func (s *sessions) create() (token string, expires time.Time) {
	return s.createKind(kindFull, 0, s.ttl)
}

func (s *sessions) createKind(kind string, gen int64, ttl time.Duration) (token string, expires time.Time) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic("api: no randomness: " + err.Error())
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	expires = s.now().Add(ttl)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	for len(s.m) >= maxSessions { // drop the oldest rather than refuse the owner
		var oldest [32]byte
		var first = true
		for k, v := range s.m {
			if first || v.expires.Before(s.m[oldest].expires) {
				oldest, first = k, false
			}
		}
		delete(s.m, oldest)
	}
	s.m[sha256.Sum256([]byte(token))] = session{expires: expires, kind: kind, gen: gen}
	return token, expires
}

// valid reports whether the token is a live full session.
func (s *sessions) valid(token string) bool {
	sess, ok := s.lookup(token)
	return ok && sess.kind == kindFull
}

func (s *sessions) lookup(token string) (session, bool) {
	if token == "" || len(token) > 128 {
		return session{}, false
	}
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[key]
	if !ok {
		return session{}, false
	}
	if !s.now().Before(sess.expires) {
		delete(s.m, key)
		return session{}, false
	}
	return sess, true
}

func (s *sessions) revoke(token string) {
	s.mu.Lock()
	delete(s.m, sha256.Sum256([]byte(token)))
	s.mu.Unlock()
}

func (s *sessions) revokeAll() {
	s.mu.Lock()
	s.m = map[[32]byte]session{}
	s.mu.Unlock()
}

func (s *sessions) sweepLocked() {
	now := s.now()
	for k, v := range s.m {
		if !now.Before(v.expires) {
			delete(s.m, k)
		}
	}
}

// limiter counts failed sign-ins per address. Five misses in ten minutes lock
// that address out for the rest of the window; a success forgives it.
type limiter struct {
	mu    sync.Mutex
	now   func() time.Time
	limit int
	fail  map[string][]time.Time
}

func newLimiter(now func() time.Time) *limiter { return newLimiterN(now, failLimit) }

func newLimiterN(now func() time.Time, limit int) *limiter {
	return &limiter{now: now, limit: limit, fail: map[string][]time.Time{}}
}

// blocked reports whether the address may not try again yet, and for how long.
func (l *limiter) blocked(addr string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	times := l.prune(addr)
	if len(times) < l.limit {
		return false, 0
	}
	return true, times[0].Add(failWindow).Sub(l.now())
}

func (l *limiter) failed(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.fail) >= maxTrackedAddrs {
		for k := range l.fail {
			if len(l.prune(k)) == 0 {
				delete(l.fail, k)
			}
		}
		if len(l.fail) >= maxTrackedAddrs { // a flood: forget the table, keep serving
			l.fail = map[string][]time.Time{}
		}
	}
	l.fail[addr] = append(l.prune(addr), l.now())
}

func (l *limiter) ok(addr string) {
	l.mu.Lock()
	delete(l.fail, addr)
	l.mu.Unlock()
}

func (l *limiter) prune(addr string) []time.Time {
	cut := l.now().Add(-failWindow)
	times := l.fail[addr]
	i := 0
	for i < len(times) && times[i].Before(cut) {
		i++
	}
	times = times[i:]
	if len(times) == 0 {
		delete(l.fail, addr)
	} else {
		l.fail[addr] = times
	}
	return times
}
