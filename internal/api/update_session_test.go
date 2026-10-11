package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUpdateSessionCrossesOneRestartWithoutExtendingItsExpiry(t *testing.T) {
	s, st, clock := newServer(t)
	token := signIn(t, s)
	other := signIn(t, s)
	if err := s.checkpointUpdateSession(token); err != nil {
		t.Fatal(err)
	}
	raw := st.GetMeta(updateSessionKey)
	if strings.Contains(raw, token) || strings.Contains(raw, testPassword) {
		t.Fatal("plaintext credentials stored")
	}
	next, err := New(s.opt)
	if err != nil {
		t.Fatal(err)
	}
	if !next.sessions.valid(token) || next.sessions.valid(other) {
		t.Fatal("must restore only the initiating session")
	}
	*clock = clock.Add(31 * time.Minute)
	if next.sessions.valid(token) {
		t.Fatal("recovered session outlived the recovery window")
	}
	*clock = clock.Add(-31 * time.Minute)
	second, err := New(s.opt)
	if err != nil {
		t.Fatal(err)
	}
	if second.sessions.valid(token) {
		t.Fatal("recovery record replayed on a second restart")
	}
}

func TestUpdateSessionNeverExtendsAShortSession(t *testing.T) {
	s, _, clock := newServer(t)
	s.sessions.ttl = time.Minute
	token := signIn(t, s)
	if err := s.checkpointUpdateSession(token); err != nil {
		t.Fatal(err)
	}
	next, err := New(s.opt)
	if err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(2 * time.Minute)
	if next.sessions.valid(token) {
		t.Fatal("original expiry was extended")
	}
}

func TestUpdateSessionRejectsChangedCredentialsAndSetupSessions(t *testing.T) {
	s, st, _ := newServer(t)
	token := signIn(t, s)
	if err := s.checkpointUpdateSession(token); err != nil {
		t.Fatal(err)
	}
	s.sessions = newSessions(time.Hour, s.now)
	snap := s.cred.snapshot()
	if err := s.cred.set("a-different-owner", snap.hash); err != nil {
		t.Fatal(err)
	}
	s.restoreUpdateSession()
	if s.sessions.valid(token) {
		t.Fatal("credential rotation did not invalidate recovery")
	}
	setup, _ := s.sessions.createKind(kindSetup, 1, time.Hour)
	if err := s.checkpointUpdateSession(setup); err != nil {
		t.Fatal(err)
	}
	if st.GetMeta(updateSessionKey) != "" {
		t.Fatal("setup session was persisted")
	}
}

func TestUpdateSessionLogoutExpiryAndMalformedRecords(t *testing.T) {
	s, st, clock := newServer(t)
	token := signIn(t, s)
	if err := s.checkpointUpdateSession(token); err != nil {
		t.Fatal(err)
	}
	s.clearUpdateSession(token)
	if st.GetMeta(updateSessionKey) != "" {
		t.Fatal("logout did not revoke recovery")
	}
	if err := s.checkpointUpdateSession(token); err != nil {
		t.Fatal(err)
	}
	var record updateSession
	if err := json.Unmarshal([]byte(st.GetMeta(updateSessionKey)), &record); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"{", strings.Replace(st.GetMeta(updateSessionKey), record.Digest, "not-a-digest", 1)} {
		if err := st.SetMeta(updateSessionKey, raw); err != nil {
			t.Fatal(err)
		}
		s.sessions = newSessions(time.Hour, s.now)
		s.restoreUpdateSession()
		if s.sessions.valid(token) || st.GetMeta(updateSessionKey) != "" {
			t.Fatal("malformed recovery was accepted or retained")
		}
	}
	record.Until = clock.Add(-time.Minute)
	b, _ := json.Marshal(record)
	if err := st.SetMeta(updateSessionKey, string(b)); err != nil {
		t.Fatal(err)
	}
	s.restoreUpdateSession()
	if s.sessions.valid(token) {
		t.Fatal("expired recovery restored")
	}
}
