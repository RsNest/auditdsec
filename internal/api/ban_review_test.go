package api

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/decision"
	"github.com/RsNest/auditdsec/internal/model"
)

type reviewEnforcer struct {
	calls int
	err   error
}

func (e *reviewEnforcer) Ban(context.Context, action.Decision) error { e.calls++; return e.err }
func (e *reviewEnforcer) Unban(context.Context, string) error        { return nil }

func TestRepeatedPanelBanRetainsOriginalDecision(t *testing.T) {
	s, st, clock := newServer(t)
	e := &reviewEnforcer{}
	useEnforcer(s, e)
	token := signIn(t, s)
	request := map[string]string{"ip": "198.51.100.5", "duration": "1h"}
	if r := do(t, s, "POST", "/api/v1/bans", token, request); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	original := st.Bans()[0]
	*clock = clock.Add(time.Minute)
	request["duration"] = "permanent"
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := do(t, s, "POST", "/api/v1/bans", token, request)
			if r.Code != 200 {
				t.Errorf("repeat: %d %s", r.Code, r.Body)
			}
		}()
	}
	wg.Wait()
	if b := st.Bans()[0]; b != original || e.calls != 1 {
		t.Fatalf("duplicate changed decision: %+v, original %+v, firewall calls %d", b, original, e.calls)
	}
}

func TestFailedBanCanBeRetriedWithoutEscalation(t *testing.T) {
	s, st, _ := newServer(t)
	e := &reviewEnforcer{err: errors.New("refused")}
	useEnforcer(s, e)
	token := signIn(t, s)
	request := map[string]string{"ip": "198.51.100.5", "duration": "1h"}
	if r := do(t, s, "POST", "/api/v1/bans", token, request); r.Code != 502 {
		t.Fatal("firewall failure must not be success", r.Code, r.Body)
	}
	original := st.Bans()[0]
	if original.Applied {
		t.Fatal("failed ban marked applied")
	}
	e.err = nil
	if r := do(t, s, "POST", "/api/v1/bans", token, request); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	b := st.Bans()[0]
	if !b.Applied || b.Count != 1 || b.Until != original.Until || e.calls != 2 {
		t.Fatalf("retry changed offence or failed to enforce: %+v, calls %d", b, e.calls)
	}
}

func TestSuspectsAggregateBeyondEventPageAndKeepFailedEnforcementVisible(t *testing.T) {
	s, st, now := newServer(t)
	useEnforcer(s, &reviewEnforcer{})
	token := signIn(t, s)
	for ip, count := range map[string]int{
		"198.51.100.1": 1, "198.51.100.2": 5, "198.51.100.3": 230,
		"198.51.100.4": 6, "198.51.100.5": 1, "10.0.0.1": 2,
	} {
		for i := 0; i < count; i++ {
			if err := st.AppendEvent(model.Event{Time: now.Add(-time.Second), Kind: model.KindSSHLoginFail,
				Severity: model.SevWarn, SrcIP: ip}); err != nil {
				t.Fatal(err)
			}
		}
	}
	// An expired observation must not contribute to the current window.
	_ = st.AppendEvent(model.Event{Time: now.Add(-11 * time.Minute), Kind: model.KindSSHLoginFail, SrcIP: "198.51.100.1"})
	_, _, _ = st.EnsureBan("198.51.100.4", "auto", now.Add(time.Hour))
	_ = st.MarkBanApplied("198.51.100.4")
	_ = st.Allow("198.51.100.5", "owner")
	_, _, _ = st.EnsureBan("198.51.100.3", "failed firewall", now.Add(time.Hour))
	r := do(t, s, "GET", "/api/v1/suspects", token, nil)
	var page struct {
		Items     []suspectJSON `json:"items"`
		Threshold int           `json:"threshold"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &page); err != nil || r.Code != 200 {
		t.Fatal(err, r.Code, r.Body)
	}
	if len(page.Items) != 3 || page.Threshold != 6 || page.Items[0].Attempts != 230 ||
		page.Items[1].Attempts != 1 || page.Items[2].Attempts != 5 || page.Items[0].State != "needs_attention" {
		t.Fatalf("review list: %+v", page)
	}
	// Removing the backend must reveal previously applied records too.
	useEnforcer(s, nil)
	r = do(t, s, "GET", "/api/v1/suspects", token, nil)
	_ = json.Unmarshal(r.Body.Bytes(), &page)
	if len(page.Items) != 4 {
		t.Fatalf("disabled enforcement concealed a source: %s", r.Body)
	}
}

// useEnforcer swaps the firewall behind the server's decision service.
func useEnforcer(s *Server, e Enforcer) {
	var banner action.Banner
	if e != nil {
		banner = enforcerBanner{e}
	}
	s.opt.Decisions = decision.New(decision.Options{Store: s.opt.Store, Banner: banner, Now: s.now})
}
