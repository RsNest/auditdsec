package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

func TestPlanIsOfflineAndRoutesAreImmutable(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(`{"ok":true}`)) }))
	defer ts.Close()
	dir := t.TempDir()
	st, err := store.Open(store.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m, err := NewManaged(Options{Token: "123:private-token", ChatIDs: []int64{42, 43}, APIBase: ts.URL, Store: st, QuietFrom: -1, QuietTo: -1}, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	ev := model.Event{ID: "event-one", Time: time.Now(), Kind: model.KindSudo, Severity: model.SevWarn, SummaryKey: "event.sudo", Args: map[string]string{"cmd": strings.Repeat("<secret>&", 10000)}}
	plan := m.PlanEvent(ev)
	if calls.Load() != 0 || len(plan.Intents) != 2 {
		t.Fatal("planning performed I/O", calls.Load(), plan)
	}
	raw, _ := json.Marshal(plan)
	if strings.Contains(string(raw), "private-token") {
		t.Fatal("plan contains bot credentials")
	}
	if plan.Intents[0].ID == plan.Intents[1].ID || len(plan.Intents[0].DedupKey) != 64 {
		t.Fatal("fanout/dedup keys unsafe")
	}
	for _, in := range plan.Intents {
		if m.DeliveryPolicy(in).CancelReason != "" {
			t.Fatal("valid route rejected")
		}
	}
	m.mu.Lock()
	m.settings.ChatIDs = []int64{43}
	m.mu.Unlock()
	if m.DeliveryPolicy(plan.Intents[0]).CancelReason != "recipient_removed" {
		t.Fatal("removed recipient still allowed")
	}
	m.mu.Lock()
	m.settings.Token = "other-token"
	m.mu.Unlock()
	if m.DeliveryPolicy(plan.Intents[1]).CancelReason != "route_changed" {
		t.Fatal("old intent rerouted")
	}
	if err := m.SendDelivery(context.Background(), plan.Intents[1]); err == nil {
		t.Fatal("changed route sent")
	}
	if calls.Load() != 0 {
		t.Fatal("route guard sent HTTP")
	}
}

func TestPolicySuppressionAndCriticalBypass(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(store.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m, err := NewManaged(Options{Token: "secret", ChatIDs: []int64{1}, Store: st, MinSeverity: model.SevWarn, QuietFrom: -1, QuietTo: -1}, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	ev := model.Event{ID: "one", Kind: model.KindSudo, Severity: model.SevInfo}
	if m.PlanEvent(ev).Suppressed != "severity" {
		t.Fatal("severity ignored")
	}
	if err := st.Mute(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ev.Severity = model.SevWarn
	if m.PlanEvent(ev).Suppressed != "muted" {
		t.Fatal("mute ignored")
	}
	ev.Severity = model.SevCritical
	if len(m.PlanEvent(ev).Intents) != 1 {
		t.Fatal("critical muted")
	}
	m.mu.Lock()
	m.settings.Kinds = nil
	m.mu.Unlock()
	if m.PlanEvent(ev).Suppressed != "category" {
		t.Fatal("disabled critical category ignored")
	}
}

func TestDeliveryErrorsAndProviderAcknowledgment(t *testing.T) {
	for _, tc := range []struct {
		code      int
		body      string
		permanent bool
		retry     time.Duration
	}{
		{429, `{"ok":false,"error_code":429,"description":"secret","parameters":{"retry_after":7}}`, false, 7 * time.Second},
		{403, `{"ok":false,"error_code":403,"description":"secret"}`, true, 0},
		{503, `unavailable`, false, 0},
		{200, `{"ok":true}`, false, 0},
	} {
		t.Run(string(rune(tc.code)), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.code); w.Write([]byte(tc.body)) }))
			defer ts.Close()
			dir := t.TempDir()
			m, err := NewManaged(Options{Token: "secret", ChatIDs: []int64{1}, APIBase: ts.URL, QuietFrom: -1, QuietTo: -1}, dir, false)
			if err != nil {
				t.Fatal(err)
			}
			in := m.PlanEvent(model.Event{ID: "one", Kind: model.KindSudo, Severity: model.SevCritical}).Intents[0]
			err = m.SendDelivery(context.Background(), in)
			if tc.code == 200 {
				if err != nil || m.View().LastDelivery.IsZero() {
					t.Fatal(err, m.View())
				}
				return
			}
			var se *delivery.SendError
			if !errors.As(err, &se) || se.Permanent != tc.permanent || se.RetryAfter != tc.retry {
				t.Fatal(err)
			}
			if strings.Contains(err.Error(), "secret") || !m.View().LastDelivery.IsZero() {
				t.Fatal("error leaked or failure counted as delivery", err)
			}
		})
	}
}
