package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

// The same machine written differently is one identity everywhere.
func TestAddressSpellingsShareOneIdentity(t *testing.T) {
	s, _ := openTemp(t)
	until := time.Now().Add(time.Hour)
	b, created, err := s.EnsureBan("2001:DB8:0:0:0:0:0:1", "x", until)
	if err != nil || !created || b.IP != "2001:db8::1" {
		t.Fatalf("%+v %v %v", b, created, err)
	}
	if _, created, _ := s.EnsureBan("2001:db8::1", "again", until); created {
		t.Error("another spelling created a second ban")
	}
	if _, created, _ := s.EnsureBan("::ffff:203.0.113.7", "x", until); !created {
		t.Fatal("mapped address")
	}
	if got, ok := s.Ban("203.0.113.7"); !ok || got.IP != "203.0.113.7" {
		t.Errorf("the mapped form is the IPv4 address: %+v %v", got, ok)
	}
	if err := s.Allow("2001:0db8::0001", "me"); err != nil {
		t.Fatal(err)
	}
	if !s.IsAllowed("2001:DB8::1") || !s.IsAllowed("2001:db8:0:0:0:0:0:1") {
		t.Error("an allowlist entry is not recognised under another spelling")
	}
	if _, _, err := s.EnsureBan("2001:db8::1", "x", until); !errors.Is(err, ErrAllowlisted) {
		t.Errorf("err = %v", err)
	}
	if _, _, err := s.EnsureBan("not-an-ip", "x", until); !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("err = %v", err)
	}
}

func TestAllowNetworks(t *testing.T) {
	s, _ := openTemp(t)
	until := time.Now().Add(time.Hour)
	if _, _, err := s.EnsureBan("203.0.113.9", "x", until); err != nil {
		t.Fatal(err)
	}
	key, removed, err := s.AllowEntry("203.0.113.77/24", "office")
	if err != nil || key != "203.0.113.0/24" || len(removed) != 1 || removed[0].IP != "203.0.113.9" {
		t.Fatalf("%q %+v %v", key, removed, err)
	}
	if !s.IsAllowed("203.0.113.200") || s.IsAllowed("203.0.114.1") {
		t.Error("the network covers exactly its addresses")
	}
	if _, _, err := s.EnsureBan("203.0.113.5", "x", until); !errors.Is(err, ErrAllowlisted) {
		t.Errorf("a ban inside an allowlisted network: %v", err)
	}
	for _, bad := range []string{"0.0.0.0/0", "10.0.0.0/7", "::/0", "2001::/8", "203.0.113.0/33", "x/24"} {
		if _, _, err := s.AllowEntry(bad, ""); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if _, _, err := s.AllowEntry("2001:db8::/32", ""); err != nil {
		t.Errorf("a /32 IPv6 network is fine: %v", err)
	}
	if ok, _ := s.Unallow("203.0.113.0/24"); !ok || s.IsAllowed("203.0.113.200") {
		t.Error("Unallow of the network")
	}
}

// Lifting a block that the firewall has not confirmed stays on record.
func TestUnbanAndAllowLeaveReleases(t *testing.T) {
	s, dir := openTemp(t)
	until := time.Now().Add(time.Hour)
	s.EnsureBan("198.51.100.1", "x", until)
	s.EnsureBan("198.51.100.2", "x", until)
	if removed, err := s.Unban("198.51.100.1"); !removed || err != nil {
		t.Fatal(removed, err)
	}
	if _, removed, err := s.AllowEntry("198.51.100.2", "me"); err != nil || len(removed) != 1 {
		t.Fatal(removed, err)
	}
	rel := s.Releases()
	if len(rel) != 2 || rel[0].IP != "198.51.100.1" {
		t.Fatalf("releases = %+v", rel)
	}
	if err := s.UpdateRelease("198.51.100.1", errors.New("nft: busy")); err != nil {
		t.Fatal(err)
	}
	// survives a restart, with the failure on record
	s.Close()
	s2, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rel = s2.Releases()
	if len(rel) != 2 || rel[0].Attempts != 1 || rel[0].LastError != "nft: busy" {
		t.Fatalf("after restart: %+v", rel)
	}
	if err := s2.UpdateRelease("198.51.100.1", nil); err != nil || len(s2.Releases()) != 1 {
		t.Fatal(s2.Releases())
	}
	// a new decision supersedes the pending release of that address
	s2.EnsureBan("198.51.100.1", "again", until)
	if len(s2.Releases()) != 1 {
		t.Errorf("a new ban should replace the release: %+v", s2.Releases())
	}
}

func TestEnforcementStateRoundTrip(t *testing.T) {
	s, dir := openTemp(t)
	b, _, _ := s.EnsureBanWith("198.51.100.1", "x", time.Now().Add(time.Hour), BanOptions{Origin: "detector", NoticeDue: true})
	if b.State != StatePending || b.Applied || !b.NoticeDue || b.Origin != "detector" {
		t.Fatalf("%+v", b)
	}
	if err := s.MarkBanApplied("198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	b, _ = s.Ban("198.51.100.1")
	if b.State != StateApplied || !b.Applied || b.VerifiedAt.IsZero() {
		t.Fatalf("%+v", b)
	}
	s.UpdateBan("198.51.100.1", func(b *Ban) { b.State, b.LastError = StateFailed, "boom" })
	if b, _ = s.Ban("198.51.100.1"); b.Applied || b.State != StateFailed {
		t.Fatalf("a failed ban must not read as applied: %+v", b)
	}
	if err := s.ClearNotice("198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, _ := Open(Options{Dir: dir})
	defer s2.Close()
	if b, _ := s2.Ban("198.51.100.1"); b.NoticeDue || b.State != StateFailed || b.LastError != "boom" {
		t.Fatalf("after restart: %+v", b)
	}
}

// State written by earlier versions: text keys as typed, only "applied".
func TestLegacyStateIsMigrated(t *testing.T) {
	dir := t.TempDir()
	legacy := map[string]any{
		"allowlist": map[string]any{"2001:DB8::0001": map[string]any{"ip": "2001:DB8::0001", "added_at": time.Now()}},
		"bans": map[string]any{
			"2001:DB8::0002":     map[string]any{"ip": "2001:DB8::0002", "created_at": time.Now(), "count": 1, "applied": true},
			"::ffff:203.0.113.7": map[string]any{"ip": "::ffff:203.0.113.7", "created_at": time.Now(), "count": 2, "applied": false},
		},
	}
	b, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.IsAllowed("2001:db8::1") {
		t.Error("allowlist key was not canonicalised")
	}
	if b, ok := s.Ban("2001:db8::2"); !ok || b.State != StateApplied || !b.Applied {
		t.Errorf("%+v %v", b, ok)
	}
	if b, ok := s.Ban("203.0.113.7"); !ok || b.State != StatePending || b.Applied {
		t.Errorf("%+v %v", b, ok)
	}
}
