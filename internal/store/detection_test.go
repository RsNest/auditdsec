package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/exception"
	"github.com/RsNest/auditdsec/internal/model"
)

func detectStore(t *testing.T, now *time.Time, hook func() error) *Store {
	t.Helper()
	s, err := Open(Options{Dir: t.TempDir(), RetentionDays: 7, Now: func() time.Time { return *now }, BeforeStateWrite: hook})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func failEvent(id string, at time.Time) model.Event {
	return model.Event{ID: id, Time: at, Kind: model.KindSSHLoginFail, SrcIP: "198.51.100.7"}
}

// One write records the decision and moves the cursor; a failed write records
// neither.
func TestCommitDetectionIsAtomic(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	var fail error
	s := detectStore(t, &now, func() error { return fail })
	if _, err := s.InitDetection(); err != nil {
		t.Fatal(err)
	}
	c, err := s.AppendEventWithPlan(failEvent("a", now), nil)
	if err != nil || !c.Added {
		t.Fatal(err)
	}

	fail = errors.New("disk full")
	if _, err := s.CommitDetection(c.Position, []DetectBan{{IP: "198.51.100.7", Reason: "r", Until: now.Add(time.Hour)}}); err == nil {
		t.Fatal("want the write failure")
	}
	if _, ok := s.Ban("198.51.100.7"); ok || s.DetectionCursors()[c.Position.Day] != 0 {
		t.Fatal("a failed commit left a decision or moved the cursor")
	}

	fail = nil
	res, err := s.CommitDetection(c.Position, []DetectBan{{IP: "198.51.100.7", Reason: "r", Until: now.Add(time.Hour)}})
	if err != nil || len(res) != 1 || !res[0].Created || !res[0].Ban.NoticeDue {
		t.Fatalf("%+v %v", res, err)
	}
	if s.DetectionCursors()[c.Position.Day] != c.Position.End {
		t.Fatal("the cursor did not move with the decision")
	}
	// Committing the same position again is a no-op: no second offence.
	if res, err := s.CommitDetection(c.Position, []DetectBan{{IP: "198.51.100.7", Reason: "r", Until: now.Add(time.Hour)}}); err != nil || res != nil {
		t.Fatalf("repeat: %+v %v", res, err)
	}
	if b, _ := s.Ban("198.51.100.7"); b.Count != 1 {
		t.Fatalf("repeat commit counted another offence: %+v", b)
	}
}

// An active ban is not extended by a later event; a protected address is
// refused; in both cases the cursor still moves.
func TestCommitDetectionActiveAndAllowlisted(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	s := detectStore(t, &now, nil)
	if _, err := s.InitDetection(); err != nil {
		t.Fatal(err)
	}
	var last delivery.Position
	for i := 0; i < 3; i++ {
		c, _ := s.AppendEventWithPlan(failEvent(fmt.Sprint("e", i), now), nil)
		last = c.Position
		var bans []DetectBan
		switch i {
		case 0, 1:
			bans = []DetectBan{{IP: "198.51.100.7", Reason: "r", Until: now.Add(time.Hour * time.Duration(i+1))}}
		case 2:
			if err := s.Allow("203.0.113.9", ""); err != nil {
				t.Fatal(err)
			}
			bans = []DetectBan{{IP: "203.0.113.9", Reason: "r", Until: now.Add(time.Hour)}}
		}
		res, err := s.CommitDetection(c.Position, bans)
		if err != nil {
			t.Fatal(err)
		}
		switch i {
		case 0:
			if !res[0].Created {
				t.Fatal("first decision not created")
			}
		case 1:
			if res[0].Created {
				t.Fatal("an active ban was re-created")
			}
		case 2:
			if !errors.Is(res[0].Err, ErrAllowlisted) {
				t.Fatalf("allowlisted: %+v", res[0])
			}
		}
	}
	b, _ := s.Ban("198.51.100.7")
	if b.Count != 1 || !b.Until.Equal(now.Add(time.Hour)) {
		t.Errorf("the active ban was extended or recounted: %+v", b)
	}
	if _, ok := s.Ban("203.0.113.9"); ok || s.DetectionCursors()[last.Day] != last.End {
		t.Error("allowlisted address banned, or progress stuck")
	}
}

// First initialization on an existing journal starts at its end; later calls
// keep the progress; lost or damaged progress is an error.
func TestInitDetectionMigrationAndIntegrity(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	open := func() *Store {
		s, err := Open(Options{Dir: dir, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := open()
	for i := 0; i < 3; i++ {
		s.AppendEvent(failEvent(fmt.Sprint("old", i), now.Add(-time.Hour)))
	}
	skipped, err := s.InitDetection()
	if err != nil || skipped != 1 {
		t.Fatalf("migration: %d %v", skipped, err)
	}
	called := false
	if err := s.ConsumeDetection(func(delivery.Position, model.Event) error { called = true; return nil }); err != nil || called {
		t.Fatalf("history was offered to detection: %v %v", called, err)
	}
	s.AppendEvent(failEvent("new", now))
	got := 0
	_ = s.ConsumeDetection(func(pos delivery.Position, ev model.Event) error {
		got++
		_, err := s.CommitDetection(pos, nil)
		return err
	})
	if got != 1 {
		t.Fatalf("want only the new event, got %d", got)
	}
	s.Close()

	s = open()
	if n, err := s.InitDetection(); err != nil || n != 0 {
		t.Fatalf("second init: %d %v", n, err)
	}
	// A cursor beyond its file is refused.
	s.state.Detect.Cursors["2026-10-10"] = 1 << 30
	if _, err := s.InitDetection(); !errors.Is(err, ErrDetectionCursor) {
		t.Fatalf("corrupt cursor: %v", err)
	}
	s.Close()

	// Progress removed while the marker stays.
	if err := os.Remove(filepath.Join(dir, stateFileName)); err != nil {
		t.Fatal(err)
	}
	s = open()
	defer s.Close()
	if _, err := s.InitDetection(); !errors.Is(err, ErrDetectionLost) {
		t.Fatalf("lost progress: %v", err)
	}
}

// Retention never deletes a day that still holds input the detector owes a
// result for.
func TestPurgeKeepsUnconsumedDetectionInput(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	s := detectStore(t, &now, nil)
	old := now.AddDate(0, 0, -30)
	if _, err := s.InitDetection(); err != nil {
		t.Fatal(err)
	}
	s.AppendEvent(failEvent("old", old))
	if n, _ := s.Purge(); n != 0 {
		t.Fatalf("purged %d files holding unconsumed events", n)
	}
	err := s.ConsumeDetection(func(pos delivery.Position, _ model.Event) error {
		_, err := s.CommitDetection(pos, nil)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	s.AppendEvent(failEvent("today", now)) // the writer moves off the old day
	if n, _ := s.Purge(); n != 1 {
		t.Fatalf("a fully consumed old day should be purged, removed %d", n)
	}
	if len(s.DetectionCursors()) != 0 {
		t.Errorf("cursors are not bounded by retention: %v", s.DetectionCursors())
	}
}

// Correlation memory is rebuilt from consumed events only.
func TestRestoreConsumedStopsAtTheCursor(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	s := detectStore(t, &now, nil)
	if _, err := s.InitDetection(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s.AppendEvent(failEvent(fmt.Sprint("e", i), now.Add(time.Duration(i)*time.Second)))
	}
	n := 0
	_ = s.ConsumeDetection(func(pos delivery.Position, _ model.Event) error {
		n++
		if n > 2 {
			return errors.New("stop") // the third stays unconsumed
		}
		_, err := s.CommitDetection(pos, nil)
		return err
	})
	var restored []string
	if err := s.RestoreConsumed(now.Add(-time.Minute), func(ev model.Event) { restored = append(restored, ev.ID) }); err != nil {
		t.Fatal(err)
	}
	if len(restored) != 2 || restored[0] != "e0" || restored[1] != "e1" {
		t.Errorf("restored %v, want the two consumed events only", restored)
	}
}

func TestExceptionsPersistAndRollBack(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	var fail error
	s := detectStore(t, &now, func() error { return fail })
	r := exception.Rule{Kind: model.KindSudo, User: "root", Reason: "deploy", ExpiresAt: now.Add(time.Hour)}

	fail = errors.New("disk full")
	if _, err := s.AddException(r, "panel"); err == nil {
		t.Fatal("want the write failure")
	}
	if rules, _ := s.Exceptions(); len(rules) != 0 {
		t.Fatalf("a failed write left a rule: %+v", rules)
	}
	fail = nil
	got, err := s.AddException(r, "panel:203.0.113.1")
	if err != nil || got.ID != "exc-1" || got.CreatedBy != "panel:203.0.113.1" {
		t.Fatalf("%+v %v", got, err)
	}
	ev := model.Event{Kind: model.KindSudo, Severity: model.SevInfo, User: "root"}
	if x, ok := s.MatchException(ev); !ok || x.ID != "exc-1" {
		t.Fatal("no match")
	}
	if _, hits := s.Exceptions(); hits["exc-1"].Count != 1 {
		t.Errorf("hits: %+v", hits)
	}
	if err := s.RemoveException("exc-9"); !errors.Is(err, ErrNoException) {
		t.Errorf("%v", err)
	}
	if err := s.RemoveException("exc-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.MatchException(ev); ok {
		t.Error("a removed exception still matches")
	}
	// IDs are not reused.
	if next, _ := s.AddException(r, "x"); next.ID != "exc-2" {
		t.Errorf("%s", next.ID)
	}
	// Expired rules are dropped after the keep period, and the number is capped.
	now = now.Add(exception.MaxLife + exception.KeepExpiry + 24*time.Hour)
	r.ExpiresAt = now.Add(time.Hour)
	if _, err := s.AddException(r, "x"); err != nil {
		t.Fatal(err)
	}
	if rules, _ := s.Exceptions(); len(rules) != 1 {
		t.Errorf("old rules were not pruned: %d", len(rules))
	}
	for i := 0; i < exception.MaxRules; i++ {
		if _, err := s.AddException(r, "x"); err != nil {
			if !errors.Is(err, exception.ErrInvalid) {
				t.Fatal(err)
			}
			return
		}
	}
	t.Error("the number of exceptions is not capped")
}
