package delivery

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type retrySender struct {
	mu      sync.Mutex
	calls   map[string]int
	retryID string
}

func (s *retrySender) DeliveryPolicy(Intent) Policy { return Policy{RatePerMinute: 1000} }
func (s *retrySender) SendDelivery(_ context.Context, in Intent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[in.ID]++
	if in.ID == s.retryID && s.calls[in.ID] == 1 {
		return &SendError{Code: "telegram_429", RetryAfter: 20 * time.Second}
	}
	return nil
}

func TestRetryDeadlineAndRecipientProgressSurviveRestart(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	o := testOptions(t)
	o.Now = func() time.Time { return time.Unix(0, clock.Load()) }
	q := openTest(t, o)
	a, b := intent("a", Routine), intent("b", Routine)
	a.Created, b.Created = o.Now(), o.Now()
	if err := q.Import(pos(0), Plan{Intents: []Intent{a, b}}); err != nil {
		t.Fatal(err)
	}
	s := &retrySender{calls: map[string]int{}, retryID: b.ID}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx, s) }()
	eventually(t, func() bool { return q.Stats().Delivered == 1 && q.Stats().Retries == 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	next := q.s.Jobs[b.ID].NextAttempt
	q.mu.Unlock()
	if next.Before(o.Now().Add(20 * time.Second)) {
		t.Fatal("provider retry_after ignored", next)
	}
	_ = q.Close()
	clock.Add(int64(30 * time.Second))
	q = openTest(t, o)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	done = make(chan error, 1)
	go func() { done <- q.Run(ctx, s) }()
	eventually(t, func() bool { return q.Stats().Delivered == 2 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls[a.ID] != 1 || s.calls[b.ID] != 2 {
		t.Fatal("successful recipient resent", s.calls)
	}
}

func TestEmptyInitializedWALFailsClosed(t *testing.T) {
	o := testOptions(t)
	q := openTest(t, o)
	_ = q.Close()
	if err := os.WriteFile(filepath.Join(o.Dir, "outbox.wal"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(o); err == nil {
		t.Fatal("empty initialized WAL treated as new")
	}
}

func TestCriticalEvidenceCannotGroupBehindRoutine(t *testing.T) {
	r := intent("routine", Routine)
	r.DedupKey = "same"
	r.Severity = 1
	c := r
	c.ID = ID("critical")
	c.Priority = Critical
	c.Severity = 2
	if groupKey(r) == groupKey(c) {
		t.Fatal("critical event can inherit routine grouping window")
	}
}
