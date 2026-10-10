package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
)

func TestStableIDSurvivesRestartAndBloomCollision(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	o := Options{Dir: dir, Now: func() time.Time { return now }}
	s, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	ev := event(now, model.KindSudo, model.SevInfo, "")
	ev.ID = "stable-source-event"
	if added, err := s.AppendEventOnce(ev); err != nil || !added {
		t.Fatal(added, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if added, err := s.AppendEventOnce(ev); err != nil || added {
		t.Fatal("replay appended duplicate", added, err)
	}
	i := s.indexes[now.Format(dayLayout)]
	for n := range i.bits {
		i.bits[n] = 255
	}
	ev.ID = "new-event-after-bloom-collision"
	if added, err := s.AppendEventOnce(ev); err != nil || !added {
		t.Fatal("Bloom false positive dropped an event", added, err)
	}
	if len(s.Recent(0)) != 2 {
		t.Fatal("duplicate entered recent events")
	}
}

func TestStableIDOutsideRecentCacheUsesJournal(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	if err := os.MkdirAll(filepath.Join(dir, eventsDirName), 0750); err != nil {
		t.Fatal(err)
	}
	var data strings.Builder
	for n := 0; n <= recentIDs; n++ {
		ev := event(now, model.KindSudo, model.SevInfo, "")
		ev.ID = fmt.Sprintf("%064x", n)
		b, _ := json.Marshal(ev)
		data.Write(b)
		data.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, eventsDirName, now.Format(dayLayout)+".jsonl"), []byte(data.String()), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(Options{Dir: dir, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ev := event(now, model.KindSudo, model.SevInfo, "")
	ev.ID = fmt.Sprintf("%064x", 0)
	if added, err := s.AppendEventOnce(ev); err != nil || added {
		t.Fatal("evicted ID was appended twice", added, err)
	}
}

func TestTornJournalTailIsRepairedBeforeAppend(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	s, err := Open(Options{Dir: dir, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ev := event(now, model.KindSudo, model.SevInfo, "")
	ev.ID = "first"
	if err := s.AppendEvent(ev); err != nil {
		t.Fatal(err)
	}
	s.Close()
	path := filepath.Join(dir, eventsDirName, now.Format(dayLayout)+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"event_id":"unfinished`)
	f.Close()
	s, err = Open(Options{Dir: dir, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ev.ID = "second"
	if err := s.AppendEvent(ev); err != nil {
		t.Fatal(err)
	}
	evs, err := s.readDay(now.Format(dayLayout))
	if err != nil || len(evs) != 2 || evs[1].ID != "second" {
		t.Fatal("torn tail swallowed the next event", evs, err)
	}
}

func TestFailedAppendDoesNotChangeRecentOrAcceptMoreWrites(t *testing.T) {
	s := testStore(t, time.Now)
	ev := event(time.Now(), model.KindSudo, model.SevInfo, "")
	if err := s.AppendEvent(ev); err != nil {
		t.Fatal(err)
	}
	s.f.Close()
	if err := s.AppendEvent(ev); err == nil {
		t.Fatal("write to closed journal succeeded")
	}
	if len(s.Recent(0)) != 1 {
		t.Fatal("failed append was visible as stored")
	}
	if err := s.AppendEvent(ev); err == nil {
		t.Fatal("failed journal accepted another write")
	}
}
