package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
)

func testStore(t *testing.T, now func() time.Time) *Store {
	t.Helper()
	s, err := Open(Options{Dir: t.TempDir(), MaxRecent: 5, RetentionDays: 2, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func event(ts time.Time, kind model.Kind, sev model.Severity, ip string) model.Event {
	return model.Event{
		Time: ts, Host: "web01", Kind: kind, Severity: sev, SrcIP: ip,
		SummaryKey: "event." + string(kind), Args: map[string]string{"ip": ip},
	}
}

func TestAppendAndRecent(t *testing.T) {
	base := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	s := testStore(t, func() time.Time { return base })

	for i := 0; i < 7; i++ {
		ev := event(base.Add(time.Duration(i)*time.Minute), model.KindSudo, model.SevInfo, "")
		ev.Args["n"] = string(rune('a' + i))
		if err := s.AppendEvent(ev); err != nil {
			t.Fatal(err)
		}
	}

	// MaxRecent is 5, so only the newest five are kept in memory.
	got := s.Recent(0)
	if len(got) != 5 {
		t.Fatalf("Recent = %d events, want 5", len(got))
	}
	if got[0].Args["n"] != "c" || got[4].Args["n"] != "g" {
		t.Errorf("wrong window: first=%q last=%q", got[0].Args["n"], got[4].Args["n"])
	}
	if got := s.Recent(2); len(got) != 2 || got[1].Args["n"] != "g" {
		t.Errorf("Recent(2) = %+v", got)
	}
}

func TestAppendWritesOnePerDayFile(t *testing.T) {
	base := time.Date(2026, 10, 9, 23, 59, 0, 0, time.UTC)
	s := testStore(t, func() time.Time { return base })

	if err := s.AppendEvent(event(base, model.KindSudo, model.SevInfo, "")); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendEvent(event(base.Add(2*time.Minute), model.KindSudo, model.SevInfo, "")); err != nil {
		t.Fatal(err)
	}
	for _, day := range []string{"2026-10-09", "2026-10-10"} {
		path := filepath.Join(s.dir, eventsDirName, day+".jsonl")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected file for %s: %v", day, err)
		}
	}
}

func TestStats(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	s := testStore(t, func() time.Time { return now })

	must := func(ev model.Event) {
		t.Helper()
		if err := s.AppendEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	must(event(now.Add(-30*time.Minute), model.KindSSHLoginFail, model.SevWarn, "1.2.3.4"))
	must(event(now.Add(-20*time.Minute), model.KindAuthorizedKeysChange, model.SevCritical, ""))
	must(event(now.Add(-26*time.Hour), model.KindSudo, model.SevInfo, "")) // outside the window

	st, err := s.Stats(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 2 {
		t.Errorf("Total = %d, want 2", st.Total)
	}
	if st.Critical != 1 {
		t.Errorf("Critical = %d, want 1", st.Critical)
	}
	if !st.Last.Equal(now.Add(-20 * time.Minute)) {
		t.Errorf("Last = %v", st.Last)
	}
	if st.ByKind[model.KindSSHLoginFail] != 1 {
		t.Errorf("ByKind = %v", st.ByKind)
	}
}

func TestAllowlist(t *testing.T) {
	now := time.Now()
	s := testStore(t, func() time.Time { return now })

	if s.IsAllowed("1.2.3.4") {
		t.Error("nothing should be allowlisted yet")
	}
	if err := s.Allow("1.2.3.4", "owner"); err != nil {
		t.Fatal(err)
	}
	if !s.IsAllowed("1.2.3.4") {
		t.Error("address should be allowlisted")
	}
	if l := s.Allowlist(); len(l) != 1 || l[0].Note != "owner" {
		t.Errorf("Allowlist = %+v", l)
	}
	removed, err := s.Unallow("1.2.3.4")
	if err != nil || !removed {
		t.Fatalf("Unallow = %v, %v", removed, err)
	}
	if removed, _ := s.Unallow("1.2.3.4"); removed {
		t.Error("second Unallow should report false")
	}
}

// The allowlist must win over any ban, so an owner cannot be locked out by
// their own agent.
func TestBanRefusedForAllowlisted(t *testing.T) {
	now := time.Now()
	s := testStore(t, func() time.Time { return now })
	if err := s.Allow("1.2.3.4", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordBan("1.2.3.4", "brute force", now.Add(time.Hour)); !errors.Is(err, ErrAllowlisted) {
		t.Fatalf("RecordBan error = %v, want ErrAllowlisted", err)
	}
	if len(s.Bans()) != 0 {
		t.Error("no ban should have been recorded")
	}
}

// Allowlisting an address that is already banned must lift the ban.
func TestAllowClearsExistingBan(t *testing.T) {
	now := time.Now()
	s := testStore(t, func() time.Time { return now })
	if _, err := s.RecordBan("5.6.7.8", "brute force", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Allow("5.6.7.8", "that was me"); err != nil {
		t.Fatal(err)
	}
	if len(s.Bans()) != 0 {
		t.Errorf("ban should be gone, got %+v", s.Bans())
	}
}

func TestBanCounterEscalates(t *testing.T) {
	now := time.Now()
	s := testStore(t, func() time.Time { return now })

	b, err := s.RecordBan("9.9.9.9", "ssh brute force", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if b.Count != 1 || b.Permanent() {
		t.Fatalf("first ban = %+v", b)
	}
	b, _ = s.RecordBan("9.9.9.9", "ssh brute force", now.Add(24*time.Hour))
	if b.Count != 2 {
		t.Errorf("Count = %d, want 2", b.Count)
	}
	b, _ = s.RecordBan("9.9.9.9", "repeat offender", time.Time{})
	if !b.Permanent() || !b.Active(now.Add(10*365*24*time.Hour)) {
		t.Errorf("permanent ban = %+v", b)
	}

	removed, err := s.Unban("9.9.9.9")
	if err != nil || !removed {
		t.Fatalf("Unban = %v, %v", removed, err)
	}
	if removed, _ := s.Unban("9.9.9.9"); removed {
		t.Error("second Unban should report false")
	}
}

func TestBanActive(t *testing.T) {
	now := time.Now()
	b := Ban{Until: now.Add(time.Hour)}
	if !b.Active(now) || b.Active(now.Add(2*time.Hour)) {
		t.Error("Active is wrong for a timed ban")
	}
}

func TestMute(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	cur := now
	s := testStore(t, func() time.Time { return cur })

	if !s.MutedUntil().IsZero() {
		t.Error("should not be muted initially")
	}
	until := now.Add(24 * time.Hour)
	if err := s.Mute(until); err != nil {
		t.Fatal(err)
	}
	if got := s.MutedUntil(); !got.Equal(until) {
		t.Errorf("MutedUntil = %v, want %v", got, until)
	}
	cur = until.Add(time.Minute) // the deadline passes
	if !s.MutedUntil().IsZero() {
		t.Error("an expired mute must read as not muted")
	}
}

func TestMetaAndStateSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	s, err := Open(Options{Dir: dir, Now: nowFn})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta("tg_offset", "4242"); err != nil {
		t.Fatal(err)
	}
	if err := s.Allow("10.0.0.1", "home"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordBan("203.0.113.5", "brute force", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendEvent(event(now, model.KindSudo, model.SevInfo, "")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(Options{Dir: dir, Now: nowFn})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := s2.GetMeta("tg_offset"); got != "4242" {
		t.Errorf("GetMeta = %q", got)
	}
	if !s2.IsAllowed("10.0.0.1") {
		t.Error("allowlist did not survive a restart")
	}
	if len(s2.Bans()) != 1 {
		t.Errorf("bans did not survive a restart: %+v", s2.Bans())
	}
	if len(s2.Recent(0)) != 1 {
		t.Errorf("recent events were not reloaded: %d", len(s2.Recent(0)))
	}
}

func TestPurgeDropsOldDays(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	s := testStore(t, func() time.Time { return now }) // retention: 2 days

	days := []string{"2026-10-01", "2026-10-06", "2026-10-08", "2026-10-09"}
	for _, d := range days {
		path := filepath.Join(s.dir, eventsDirName, d+".jsonl")
		if err := os.WriteFile(path, []byte("{}\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	// A file that is not an event log must be left alone.
	keep := filepath.Join(s.dir, eventsDirName, "notes.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}

	removed, err := s.Purge()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	for _, d := range []string{"2026-10-08", "2026-10-09"} {
		if _, err := os.Stat(filepath.Join(s.dir, eventsDirName, d+".jsonl")); err != nil {
			t.Errorf("%s should have been kept: %v", d, err)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("notes.txt should have been kept: %v", err)
	}
}

func TestPurgeDisabled(t *testing.T) {
	s, err := Open(Options{Dir: t.TempDir(), RetentionDays: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n, err := s.Purge(); n != 0 || err != nil {
		t.Errorf("Purge = %d, %v", n, err)
	}
}

func TestOpenRequiresDir(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Error("Open without Dir should fail")
	}
}

// A truncated last line (a crash mid-write) must not break reading the day.
func TestReadDaySkipsBrokenLines(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	s := testStore(t, func() time.Time { return now })
	path := filepath.Join(s.dir, eventsDirName, "2026-10-09.jsonl")
	content := `{"time":"2026-10-09T11:00:00Z","kind":"sudo","severity":0}
{"time":"2026-10-09T11:30:00Z","kind":"sudo","sever`
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	st, err := s.Stats(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 1 {
		t.Errorf("Total = %d, want 1 (the broken line is skipped)", st.Total)
	}
}
