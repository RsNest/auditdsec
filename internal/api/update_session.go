package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

const updateSessionKey = "update_session"

// Only the session that starts an update can cross its restart, once, for at
// most 30 minutes and never beyond its existing expiry. Store token digests,
// not tokens or passwords. A credentials change makes the record unusable.
type updateSession struct {
	Digest string    `json:"digest"`
	Creds  string    `json:"credentials"`
	Until  time.Time `json:"until"`
}

func (s *Server) credentialFingerprint() string {
	snap := s.cred.snapshot()
	if !snap.ready {
		return ""
	}
	b := append(append([]byte{}, snap.sum[:]...), snap.hash.key...)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *Server) checkpointUpdateSession(token string) error {
	sess, ok := s.sessions.lookup(token)
	if !ok || sess.kind != kindFull {
		return nil
	}
	until := s.now().Add(30 * time.Minute)
	if sess.expires.Before(until) {
		until = sess.expires
	}
	sum := sha256.Sum256([]byte(token))
	b, err := json.Marshal(updateSession{Digest: hex.EncodeToString(sum[:]), Creds: s.credentialFingerprint(), Until: until})
	if err != nil {
		return err
	}
	return s.opt.Store.SetMeta(updateSessionKey, string(b))
}

func (s *Server) restoreUpdateSession() {
	var record updateSession
	raw := s.opt.Store.GetMeta(updateSessionKey)
	if raw == "" {
		return
	}
	// Consume even invalid records; a normal later restart cannot replay one.
	if s.opt.Store.SetMeta(updateSessionKey, "") != nil {
		return
	}
	if json.Unmarshal([]byte(raw), &record) != nil || !s.now().Before(record.Until) ||
		record.Until.After(s.now().Add(30*time.Minute)) || record.Creds == "" || record.Creds != s.credentialFingerprint() {
		return
	}
	b, err := hex.DecodeString(record.Digest)
	if err != nil || len(b) != sha256.Size {
		return
	}
	var sum [sha256.Size]byte
	copy(sum[:], b)
	s.sessions.mu.Lock()
	s.sessions.m[sum] = session{expires: record.Until, kind: kindFull}
	s.sessions.mu.Unlock()
}

func (s *Server) clearUpdateSession(token string) {
	var record updateSession
	if json.Unmarshal([]byte(s.opt.Store.GetMeta(updateSessionKey)), &record) != nil {
		return
	}
	sum := sha256.Sum256([]byte(token))
	if record.Digest == hex.EncodeToString(sum[:]) {
		_ = s.opt.Store.SetMeta(updateSessionKey, "")
	}
}
