package delivery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testOptions(t *testing.T) Options {
	t.Helper()
	return Options{Dir: filepath.Join(t.TempDir(), "outbox"), MaxJobs: 4, MaxBytes: 4096, CriticalJobs: 1, CriticalBytes: 1024}
}
func intent(id string, priority Priority) Intent {
	return Intent{ID: ID(id), Channel: "telegram", Route: "fingerprint", Destination: "1", Priority: priority, Created: time.Now(), Payload: []byte(`{"text":"hello"}`)}
}
func pos(n int64) Position { return Position{Day: "2026-10-10", Start: n, End: n + 1} }
func openTest(t *testing.T, o Options) *Queue {
	t.Helper()
	q, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q
}

func TestReceiptCapacityAndRestart(t *testing.T) {
	o := testOptions(t)
	q := openTest(t, o)
	for n := int64(0); n < 4; n++ {
		if err := q.Import(pos(n), Plan{Intents: []Intent{intent(string(rune('a'+n)), Routine)}}); err != nil {
			t.Fatal(err)
		}
	}
	if q.Stats().Pending != 3 || q.Stats().Overflow != 1 {
		t.Fatal(q.Stats())
	}
	if err := q.Import(pos(4), Plan{Intents: []Intent{intent("critical", Critical)}}); err != nil {
		t.Fatal(err)
	}
	if err := q.Import(pos(5), Plan{Intents: []Intent{intent("full", Critical)}}); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	if q.Cursors()[pos(0).Day] != 5 {
		t.Fatal(q.Cursors())
	}
	_ = q.Close()
	q = openTest(t, o)
	if q.Stats().Pending != 4 || q.Stats().Critical != 1 || q.Stats().Overflow != 1 {
		t.Fatal(q.Stats())
	}
	if err := q.Import(pos(4), Plan{Intents: []Intent{intent("critical", Critical)}}); err != nil {
		t.Fatal(err)
	}
	if q.Stats().Pending != 4 {
		t.Fatal("receipt recreated jobs")
	}
}

func TestTornTailAndMissingStateFailClosed(t *testing.T) {
	o := testOptions(t)
	q := openTest(t, o)
	if err := q.Import(pos(0), Plan{Suppressed: "disabled"}); err != nil {
		t.Fatal(err)
	}
	_ = q.Close()
	f, err := os.OpenFile(filepath.Join(o.Dir, "outbox.wal"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"version":`)
	_ = f.Close()
	q = openTest(t, o)
	if q.Stats().Suppressed != 1 {
		t.Fatal(q.Stats())
	}
	_ = q.Close()
	if err := os.Remove(filepath.Join(o.Dir, "outbox.wal")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(o); err == nil {
		t.Fatal("missing initialized state accepted")
	}
}

func TestCorruptionAndFailedWrite(t *testing.T) {
	o := testOptions(t)
	q := openTest(t, o)
	_ = q.f.Close()
	if err := q.Import(pos(0), Plan{Intents: []Intent{intent("x", Routine)}}); err == nil {
		t.Fatal("closed WAL accepted")
	}
	if q.Stats().Pending != 0 || len(q.Cursors()) != 0 {
		t.Fatal("failed write mutated state")
	}
	if err := os.WriteFile(q.path, []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(o); err == nil {
		t.Fatal("corrupt committed record accepted")
	}
}

func TestCompactionOwnsPayload(t *testing.T) {
	o := testOptions(t)
	o.CompactAfter = 1
	q := openTest(t, o)
	in := intent("x", Routine)
	if err := q.Import(pos(0), Plan{Intents: []Intent{in}}); err != nil {
		t.Fatal(err)
	}
	in.Payload[0] = '!'
	_ = q.Close()
	q = openTest(t, o)
	if q.Stats().Pending != 1 {
		t.Fatal(q.Stats())
	}
	if err := q.Import(Position{Day: pos(0).Day, Start: 3, End: 4}, Plan{}); !errors.Is(err, ErrGap) {
		t.Fatal(err)
	}
}

type fakeSender struct {
	mu    sync.Mutex
	calls map[string]int
	fail  bool
	block <-chan struct{}
}

func (s *fakeSender) DeliveryPolicy(Intent) Policy { return Policy{RatePerMinute: 1000} }
func (s *fakeSender) SendDelivery(ctx context.Context, in Intent) error {
	if in.Priority == Routine && s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[in.ID]++
	if s.fail {
		return &SendError{Code: "forbidden", Permanent: true}
	}
	return nil
}
func eventually(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

func TestCriticalWorkerIndependentAndConfirmedReceipt(t *testing.T) {
	o := testOptions(t)
	q := openTest(t, o)
	blocked := make(chan struct{})
	s := &fakeSender{calls: map[string]int{}, block: blocked}
	for n, p := range []Priority{Routine, Critical} {
		if err := q.Import(pos(int64(n)), Plan{Intents: []Intent{intent(string(p), p)}}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx, s) }()
	eventually(t, func() bool { return q.Stats().Delivered == 1 })
	if q.Stats().Pending != 1 {
		t.Fatal(q.Stats())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = q.Close()
	q = openTest(t, o)
	if q.Stats().Delivered != 1 || q.Stats().Pending != 1 {
		t.Fatal(q.Stats())
	}
	if err := q.Import(pos(1), Plan{Intents: []Intent{intent("critical", Critical)}}); err != nil {
		t.Fatal(err)
	}
	if q.Stats().Pending != 1 {
		t.Fatal("confirmed recipient recreated")
	}
}

func TestGroupOnlyAfterSuccessAndSurvivesRestart(t *testing.T) {
	o := testOptions(t)
	q := openTest(t, o)
	a := intent("a", Routine)
	a.DedupKey = "same"
	a.DedupWindow = time.Hour
	b := a
	b.ID = ID("b")
	for n, in := range []Intent{a, b} {
		if err := q.Import(pos(int64(n)), Plan{Intents: []Intent{in}}); err != nil {
			t.Fatal(err)
		}
	}
	s := &fakeSender{calls: map[string]int{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx, s) }()
	eventually(t, func() bool { return q.Stats().Grouped == 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = q.Close()
	q = openTest(t, o)
	if q.Stats().Delivered != 1 || q.s.Groups[groupKey(a)].Extra != 1 {
		t.Fatal(q.Stats(), q.s.Groups)
	}
	q.mu.Lock()
	err := q.flushGroups(time.Now().Add(2 * time.Hour))
	q.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if q.Stats().Pending != 1 {
		t.Fatal("summary not durable")
	}
	for _, j := range q.s.Jobs {
		if j.GroupedCount != 1 {
			t.Fatal(j)
		}
	}
	// A rejection must never create a grouping window that swallows successors.
	o = testOptions(t)
	q = openTest(t, o)
	s = &fakeSender{calls: map[string]int{}, fail: true}
	for n, in := range []Intent{a, b} {
		if err := q.Import(pos(int64(n)), Plan{Intents: []Intent{in}}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() { done <- q.Run(ctx, s) }()
	eventually(t, func() bool { return q.Stats().Failed == 2 })
	cancel()
	<-done
	if q.Stats().Grouped != 0 || len(q.s.Groups) != 0 {
		t.Fatal(q.Stats())
	}
}

func TestProtectedRateShare(t *testing.T) {
	now := time.Now()
	rates := map[string]*bucket{}
	r := intent("r", Routine)
	c := intent("c", Critical)
	for n := 0; n < 16; n++ {
		if admit(rates, r, 20, now) != 0 {
			t.Fatal("routine burst too small")
		}
	}
	if admit(rates, r, 20, now) == 0 {
		t.Fatal("routine consumed reserve")
	}
	if admit(rates, c, 20, now) != 0 {
		t.Fatal("critical share unavailable")
	}
}
