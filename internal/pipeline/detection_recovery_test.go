package pipeline

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/detect"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

// The tests in this file stand a "process" up over a state directory, kill it
// at a chosen boundary (by failing a write or by simply not running a step) and
// stand a new one up over the same directory. Time, storage faults and the
// firewall are all fakes under the test's control.

const attacker = "198.51.100.7"

// listBanner is a firewall that can be listed, so the reconciler can see it.
type listBanner struct {
	mu    sync.Mutex
	elems map[string]time.Time
	bans  int // Ban calls
	fail  error
}

func newListBanner() *listBanner { return &listBanner{elems: map[string]time.Time{}} }

func (b *listBanner) Ban(_ context.Context, d action.Decision) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bans++
	if b.fail != nil {
		return b.fail
	}
	b.elems[d.IP] = d.Until
	return nil
}
func (b *listBanner) Unban(_ context.Context, ip string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.elems, ip)
	return nil
}
func (b *listBanner) List(context.Context) ([]action.Decision, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []action.Decision
	for ip, until := range b.elems {
		out = append(out, action.Decision{IP: ip, Until: until})
	}
	return out, nil
}
func (b *listBanner) Name() string { return "list" }
func (b *listBanner) has(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.elems[ip]
	return ok
}
func (b *listBanner) banCalls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bans
}

// banPlanner makes real notification plans for bans, with the stable intent
// ID the production planner derives from the decision.
type banPlanner struct{ plannedNotifier }

func (*banPlanner) PlanBan(b store.Ban, _ error) delivery.Plan {
	return delivery.Plan{Intents: []delivery.Intent{{
		ID:      delivery.ID(b.IP, b.CreatedAt.Format(time.RFC3339Nano), fmt.Sprint(b.Count)),
		Channel: "telegram", Route: "fake", Destination: "1", Priority: delivery.Critical,
		Created: b.CreatedAt, Payload: []byte(`{"text":"banned"}`),
	}}}
}

var errDisk = errors.New("injected: disk full")

type lab struct {
	t   *testing.T
	dir string
	now time.Time
	fw  *listBanner

	mu      sync.Mutex
	allow   int // state writes still allowed; negative: unlimited
	writes  int
	planner bool
}

func newLab(t *testing.T) *lab {
	t.Helper()
	l := &lab{t: t, dir: t.TempDir(), now: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC), fw: newListBanner(), allow: -1}
	if err := os.WriteFile(filepath.Join(l.dir, "audit.log"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return l
}

// failStateWritesAfter lets n more state writes through and fails the rest.
func (l *lab) failStateWritesAfter(n int) { l.mu.Lock(); l.allow = n; l.mu.Unlock() }
func (l *lab) healStateWrites()           { l.mu.Lock(); l.allow = -1; l.mu.Unlock() }

type proc struct {
	l  *lab
	st *store.Store
	p  *Pipeline
	n  Notifier
}

func (l *lab) boot() *proc {
	l.t.Helper()
	st, err := store.Open(store.Options{Dir: l.dir, Now: func() time.Time { return l.now }, BeforeStateWrite: func() error {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.writes++
		if l.allow == 0 {
			return errDisk
		}
		if l.allow > 0 {
			l.allow--
		}
		return nil
	}})
	if err != nil {
		l.t.Fatal(err)
	}
	var n Notifier = &fakeNotifier{}
	if l.planner {
		n = &banPlanner{plannedNotifier{started: make(chan struct{})}}
	}
	det := detect.NewBruteForce(detect.Options{Allowed: st.IsAllowed})
	p, err := New(Options{
		AuditLog: filepath.Join(l.dir, "audit.log"), StateDir: l.dir, Store: st, Notifier: n,
		Banner: l.fw, Detector: det, Now: func() time.Time { return l.now },
	})
	if err != nil {
		l.t.Fatal(err)
	}
	return &proc{l: l, st: st, p: p, n: n}
}

// crash drops the process without any orderly shutdown work.
func (pr *proc) crash() { _ = pr.p.Close(); _ = pr.st.Close() }

func (l *lab) failure(i int) model.Event {
	return model.Event{
		ID: fmt.Sprintf("ev-%d", i), Time: l.now.Add(time.Duration(i) * time.Second),
		Kind: model.KindSSHLoginFail, Severity: model.SevWarn, SrcIP: attacker, User: "root",
	}
}

// ingest only journals: the process dies before detection looks at the event.
func (pr *proc) ingest(ev model.Event) {
	pr.l.t.Helper()
	if _, err := pr.p.persistEvent(ev); err != nil {
		pr.l.t.Fatal(err)
	}
}

func (pr *proc) start() error { return pr.p.startDetection(context.Background()) }

func (pr *proc) ban() (store.Ban, bool) { return pr.st.Ban(attacker) }

func mustStart(t *testing.T, pr *proc) {
	t.Helper()
	if err := pr.start(); err != nil {
		t.Fatal(err)
	}
}

// Boundary 1: the sixth failure is journaled and the audit cursor has moved on,
// but the process dies before detection runs. Event deduplication would stop a
// re-read from reaching the detector; the journal backlog must not.
func TestRecoveryEventPersistedDetectionNotStarted(t *testing.T) {
	l := newLab(t)
	a := l.boot()
	mustStart(t, a)
	for i := 0; i < 6; i++ {
		a.ingest(l.failure(i))
	}
	if _, ok := a.ban(); ok {
		t.Fatal("detection ran although it was never started")
	}
	a.crash()

	l.now = l.now.Add(30 * time.Second)
	b := l.boot()
	defer b.crash()
	mustStart(t, b)
	ban, ok := b.ban()
	if !ok || ban.Count != 1 {
		t.Fatalf("the ban owed by the journaled events was lost: %+v ok=%v", ban, ok)
	}
	if n := len(b.n.(*fakeNotifier).allBans()); n != 1 {
		t.Errorf("the recovered ban was announced %d times, want 1", n)
	}
	if !l.fw.has(attacker) || ban.State != store.StateApplied {
		t.Errorf("the recovered decision was not enforced: %+v", ban)
	}

	// The same event arriving again from the audit log is a duplicate: it adds
	// nothing and decides nothing.
	if err := b.p.handle(context.Background(), l.failure(5)); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.ban(); got.Count != 1 || l.fw.banCalls() != 1 {
		t.Errorf("a duplicate event changed the decision: %+v bans=%d", got, l.fw.banCalls())
	}
}

// Boundary 2: five failures were judged before the crash, the sixth was
// computed but its result could not be written. After the restart the five are
// rebuilt from the journal and the sixth is judged exactly once.
func TestRecoveryResultNotCommittedKeepsTheThreshold(t *testing.T) {
	l := newLab(t)
	a := l.boot()
	mustStart(t, a)
	for i := 0; i < 5; i++ {
		if err := a.p.handle(context.Background(), l.failure(i)); err != nil {
			t.Fatal(err)
		}
	}
	l.failStateWritesAfter(0)
	if err := a.p.handle(context.Background(), l.failure(5)); err == nil {
		t.Fatal("a failed commit must stop the agent, not be swallowed")
	}
	if _, ok := a.ban(); ok {
		t.Fatal("a decision exists although its commit failed")
	}
	if cur := a.st.DetectionCursors(); len(cur) == 0 {
		t.Fatal("cursors vanished")
	}
	before := a.st.DetectionCursors()
	a.crash()
	l.healStateWrites()

	l.now = l.now.Add(20 * time.Second)
	b := l.boot()
	defer b.crash()
	mustStart(t, b)
	ban, ok := b.ban()
	if !ok || ban.Count != 1 {
		t.Fatalf("the threshold was lost across the restart: %+v ok=%v", ban, ok)
	}
	for day, off := range before {
		if got := b.st.DetectionCursors()[day]; got <= off {
			t.Errorf("progress did not advance past the recovered event: %d <= %d", got, off)
		}
	}
}

// Five failures before a restart plus one after still trigger the threshold.
func TestFiveBeforeRestartAndOneAfterTrigger(t *testing.T) {
	l := newLab(t)
	a := l.boot()
	mustStart(t, a)
	for i := 0; i < 5; i++ {
		if err := a.p.handle(context.Background(), l.failure(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := a.ban(); ok {
		t.Fatal("five failures must not ban")
	}
	a.crash()

	l.now = l.now.Add(time.Minute)
	b := l.boot()
	defer b.crash()
	mustStart(t, b)
	if _, ok := b.ban(); ok {
		t.Fatal("restoring history must not produce a decision")
	}
	if err := b.p.handle(context.Background(), l.failure(60)); err != nil {
		t.Fatal(err)
	}
	if ban, ok := b.ban(); !ok || ban.Count != 1 {
		t.Fatalf("5 + 1 did not reach the threshold: %+v ok=%v", ban, ok)
	}
}

// Boundary 3: the decision is committed, the firewall refuses. The decision
// stays, honestly marked, and the reconciler enforces it later without a new
// offence.
func TestRecoveryCommittedFirewallNotApplied(t *testing.T) {
	l := newLab(t)
	l.fw.fail = errors.New("nft: busy")
	a := l.boot()
	mustStart(t, a)
	for i := 0; i < 6; i++ {
		if err := a.p.handle(context.Background(), l.failure(i)); err != nil {
			t.Fatal(err)
		}
	}
	ban, ok := a.ban()
	if !ok || ban.State != store.StateFailed || ban.Applied {
		t.Fatalf("a refused ban must be recorded as failed: %+v", ban)
	}
	a.crash()

	l.fw.fail = nil
	b := l.boot()
	defer b.crash()
	mustStart(t, b)
	if got, _ := b.ban(); got.Count != 1 {
		t.Fatalf("restart re-decided the ban: %+v", got)
	}
	b.p.dec.Reconcile(context.Background())
	got, _ := b.ban()
	if got.State != store.StateApplied || !l.fw.has(attacker) || got.Count != 1 {
		t.Errorf("the reconciler did not recover the enforcement: %+v", got)
	}
}

// Boundary 4: the firewall holds the block but the state write that says so
// never happened.
func TestRecoveryFirewallAppliedCompletionNotRecorded(t *testing.T) {
	l := newLab(t)
	a := l.boot()
	mustStart(t, a)
	for i := 0; i < 5; i++ {
		if err := a.p.handle(context.Background(), l.failure(i)); err != nil {
			t.Fatal(err)
		}
	}
	l.failStateWritesAfter(1) // the commit goes through, the "applied" mark does not
	_ = a.p.handle(context.Background(), l.failure(5))
	ban, _ := a.ban()
	if !l.fw.has(attacker) || ban.State == store.StateApplied {
		t.Fatalf("setup: want a block in the firewall and no completion record: %+v", ban)
	}
	calls := l.fw.banCalls()
	a.crash()
	l.healStateWrites()

	b := l.boot()
	defer b.crash()
	mustStart(t, b)
	b.p.dec.Reconcile(context.Background())
	got, _ := b.ban()
	if got.State != store.StateApplied || got.Count != 1 {
		t.Errorf("the observed block was not adopted: %+v", got)
	}
	if l.fw.banCalls() != calls {
		t.Errorf("an element already in the firewall was added again (%d calls, was %d)", l.fw.banCalls(), calls)
	}
}

// Boundary 5: the notice was journaled but the outbox never imported it. The
// recovery imports the journaled record and does not journal a second one.
func TestRecoveryNoticeJournaledImportInterrupted(t *testing.T) {
	l := newLab(t)
	l.planner = true
	a := l.boot()
	mustStart(t, a)
	for i := 0; i < 6; i++ {
		a.ingest(l.failure(i))
	}
	// Judge them, then die while the notice is journaled but not imported: a
	// cancelled context lets the journal append succeed and stops the import.
	dying, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.p.consumeDetection(dying); err != nil {
		t.Fatal(err)
	}
	ban, ok := a.ban()
	if !ok || !ban.NoticeDue {
		t.Fatalf("setup: want a ban with its notice still owed: %+v ok=%v", ban, ok)
	}
	a.crash()

	b := l.boot()
	defer b.crash()
	mustStart(t, b)
	b.p.flushBanNotices(context.Background())

	if due := b.p.dec.DueNotices(); len(due) != 0 {
		t.Errorf("the notice duty was not settled: %+v", due)
	}
	found := 0
	_ = b.st.RecoverDeliveryPlans(map[string]int64{}, func(_ delivery.Position, p delivery.Plan) error {
		for _, in := range p.Intents {
			if in.Priority == delivery.Critical {
				found++
			}
		}
		return nil
	})
	if found != 1 {
		t.Errorf("the ban notice was journaled %d times, want 1", found)
	}
	if st := b.p.outbox.Stats(); st.Critical != 1 {
		t.Errorf("the outbox should hold exactly one ban notice job: %+v", st)
	}
}

// Recovery changes nothing the second time.
func TestRecoveryIsIdempotent(t *testing.T) {
	l := newLab(t)
	a := l.boot()
	mustStart(t, a)
	for i := 0; i < 6; i++ {
		a.ingest(l.failure(i))
	}
	a.crash()

	var created time.Time
	for round := 0; round < 3; round++ {
		l.now = l.now.Add(time.Minute)
		b := l.boot()
		mustStart(t, b)
		b.p.dec.Reconcile(context.Background())
		ban, ok := b.ban()
		if !ok || ban.Count != 1 {
			t.Fatalf("round %d: %+v", round, ban)
		}
		if round == 0 {
			created = ban.CreatedAt
		} else if !ban.CreatedAt.Equal(created) {
			t.Fatalf("round %d: the ban was re-created: %v != %v", round, ban.CreatedAt, created)
		}
		b.crash()
	}
	if l.fw.banCalls() != 1 {
		t.Errorf("the firewall was asked %d times, want 1", l.fw.banCalls())
	}
}

// A backlog whose attack ended long ago is history: it advances progress and
// bans nobody, and an allowlisted address is protected the same way.
func TestRecoveryDoesNotReviveExpiredOrProtectedDecisions(t *testing.T) {
	l := newLab(t)
	a := l.boot()
	mustStart(t, a)
	for i := 0; i < 6; i++ {
		a.ingest(l.failure(i))
	}
	a.crash()

	l.now = l.now.Add(3 * time.Hour) // the one-hour ban window is long over
	b := l.boot()
	mustStart(t, b)
	if _, ok := b.ban(); ok {
		t.Error("an expired historical decision was revived")
	}
	for day, off := range b.st.DetectionCursors() {
		if fi, err := os.Stat(filepath.Join(l.dir, "events", day+".jsonl")); err == nil && off != fi.Size() {
			t.Errorf("progress did not advance over history: %s %d/%d", day, off, fi.Size())
		}
	}
	b.crash()

	// Allowlisted: a fresh backlog for a protected address.
	l2 := newLab(t)
	c := l2.boot()
	mustStart(t, c)
	if err := c.st.Allow(attacker, "owner"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		c.ingest(l2.failure(i))
	}
	c.crash()
	d := l2.boot()
	defer d.crash()
	mustStart(t, d)
	if _, ok := d.ban(); ok || l2.fw.banCalls() != 0 {
		t.Error("an allowlisted address was banned by recovery")
	}
}

// Existing installations: events written before the first start of this
// version are history and never produce a ban; recent failures still count
// toward a threshold reached by a new event.
func TestMigrationDoesNotBanOldHistory(t *testing.T) {
	l := newLab(t)
	// A journal written by an older version: six failures an hour ago.
	old, err := store.Open(store.Options{Dir: l.dir, Now: func() time.Time { return l.now }})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		ev := l.failure(i)
		ev.Time = l.now.Add(-time.Hour).Add(time.Duration(i) * time.Second)
		ev.ID = fmt.Sprintf("old-%d", i)
		if err := old.AppendEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	old.Close()

	a := l.boot()
	defer a.crash()
	mustStart(t, a)
	if _, ok := a.ban(); ok {
		t.Fatal("old history produced a ban")
	}
	if err := a.p.handle(context.Background(), l.failure(1)); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.ban(); ok {
		t.Error("one new failure after an hour-old burst must not ban")
	}
}

// Missing or damaged progress is an error, never a silent reset to "now".
func TestMissingOrCorruptProgressIsNotSilentlyReset(t *testing.T) {
	l := newLab(t)
	a := l.boot()
	mustStart(t, a)
	a.ingest(l.failure(0))
	a.crash()

	// The progress record is lost but the marker proves it existed.
	statePath := filepath.Join(l.dir, "state.json")
	if err := os.Remove(statePath); err != nil {
		t.Skipf("state file name differs: %v", err)
	}
	b := l.boot()
	if err := b.start(); !errors.Is(err, store.ErrDetectionLost) {
		t.Errorf("lost progress: got %v", err)
	}
	b.crash()
}
