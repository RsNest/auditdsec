package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

type plannedNotifier struct {
	fakeNotifier
	started  chan struct{}
	calls    atomic.Int32
	suppress bool
}

func (f *plannedNotifier) PlanEvent(ev model.Event) delivery.Plan {
	if f.suppress {
		return delivery.Plan{Suppressed: "severity"}
	}
	return delivery.Plan{Intents: []delivery.Intent{{ID: delivery.ID(ev.ID), Channel: "telegram", Route: "fake", Destination: "1", Priority: delivery.Routine, Created: time.Now(), Payload: []byte(`{"text":"alert"}`)}}}
}
func (f *plannedNotifier) PlanBan(store.Ban, error) delivery.Plan { return delivery.Plan{} }
func (f *plannedNotifier) PlanMessage(string, map[string]string) delivery.Plan {
	return delivery.Plan{}
}
func (f *plannedNotifier) DeliveryPolicy(delivery.Intent) delivery.Policy {
	return delivery.Policy{RatePerMinute: 20}
}
func (f *plannedNotifier) SendDelivery(ctx context.Context, in delivery.Intent) error {
	if f.calls.Add(1) == 1 {
		close(f.started)
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestSlowDeliveryDoesNotBlockEventProcessing(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(audit, nil, 0600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(store.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	f := &plannedNotifier{started: make(chan struct{})}
	p, err := New(Options{AuditLog: audit, StateDir: dir, Store: st, Notifier: f})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.outbox.Run(ctx, f) }()
	for n := 0; n < 8; n++ {
		if err := p.handle(ctx, model.Event{ID: delivery.ID("event", time.Now().String()), Time: time.Now(), Kind: model.KindSSHLoginFail, Severity: model.SevWarn}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	if len(st.Recent(10)) != 8 || p.outbox.Stats().Pending != 8 {
		t.Fatal("slow provider held event processing", p.outbox.Stats())
	}
	_, reported, _ := p.Counters()
	if reported != 0 {
		t.Fatal("unconfirmed sends counted as sent")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSuppressedEventIsDurableButNotReported(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(store.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	f := &plannedNotifier{suppress: true}
	p, err := New(Options{AuditLog: filepath.Join(dir, "audit.log"), StateDir: dir, Store: st, Notifier: f})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.handle(context.Background(), model.Event{Time: time.Now(), Kind: model.KindSSHLoginOK}); err != nil {
		t.Fatal(err)
	}
	if p.outbox.Stats().Suppressed != 1 || p.outbox.Stats().Queued != 0 {
		t.Fatal(p.outbox.Stats())
	}
	_, reported, _ := p.Counters()
	if reported != 0 {
		t.Fatal("policy suppression reported as delivered")
	}
}
