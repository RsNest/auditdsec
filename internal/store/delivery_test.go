package store

import (
	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/model"
	"path/filepath"
	"testing"
	"time"
)

func TestAtomicNotificationPlanRecovery(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	ev := model.Event{ID: "stable", Time: now, Kind: model.KindSSHLoginFail}
	plan := delivery.Plan{Intents: []delivery.Intent{{ID: delivery.ID("one"), Channel: "telegram", Route: "fingerprint", Destination: "1", Priority: delivery.Routine, Created: now, Payload: []byte(`{"text":"hello"}`)}}}
	commit, err := s.AppendEventWithPlan(ev, &plan)
	if err != nil || !commit.Added {
		t.Fatal(commit, err)
	}
	// Simulate death after event sync, before any queue import.
	q, err := delivery.Open(delivery.Options{Dir: filepath.Join(dir, "outbox")})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := s.RecoverDeliveryPlans(q.Cursors(), q.Import); err != nil {
		t.Fatal(err)
	}
	if q.Stats().Pending != 1 {
		t.Fatal(q.Stats())
	}
	if again, err := s.AppendEventWithPlan(ev, &delivery.Plan{Suppressed: "changed_settings"}); err != nil || again.Added {
		t.Fatal(again, err)
	}
	if err := s.RecoverDeliveryPlans(q.Cursors(), q.Import); err != nil {
		t.Fatal(err)
	}
	if q.Stats().Queued != 1 || q.Stats().Suppressed != 0 {
		t.Fatal(q.Stats())
	}
	if len(s.Recent(10)) != 1 {
		t.Fatal("plan changed UI event shape")
	}
}

func TestLegacyHistoryDoesNotNotify(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.AppendEvent(model.Event{Time: time.Now(), Kind: model.KindSSHLoginFail}); err != nil {
		t.Fatal(err)
	}
	q, err := delivery.Open(delivery.Options{Dir: filepath.Join(dir, "outbox")})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := s.RecoverDeliveryPlans(q.Cursors(), q.Import); err != nil {
		t.Fatal(err)
	}
	if q.Stats().Queued != 0 || len(q.Cursors()) != 1 {
		t.Fatal(q.Stats(), q.Cursors())
	}
}
