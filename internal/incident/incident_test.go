package incident

import (
	"fmt"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
)

var t0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type rig struct {
	t  *testing.T
	st State
	n  int
}

func (r *rig) feed(in Input) Change {
	r.t.Helper()
	ch := Plan(&r.st, in)
	if r.st.Items == nil {
		r.st.Items = map[string]*Incident{}
	}
	for _, u := range ch.Upsert {
		r.st.Items[u.ID] = u
	}
	for _, id := range ch.Drop {
		delete(r.st.Items, id)
	}
	r.st.Seq = ch.Seq
	return ch
}

func (r *rig) ev(at time.Duration, kind model.Kind, sev model.Severity, ip string, c *model.Context) model.Event {
	r.n++
	return model.Event{ID: fmt.Sprintf("e%d", r.n), Time: t0.Add(at), Kind: kind, Severity: sev, SrcIP: ip, User: "root", Context: c}
}

func (r *rig) open() []*Incident {
	var out []*Incident
	for _, in := range r.st.Items {
		if in.State != Resolved {
			out = append(out, in)
		}
	}
	return out
}

func session(addr, conf string) *model.Context {
	return &model.Context{LoginUID: "1000", SessionID: "5", Session: &model.SessionRef{Addr: addr, Confidence: conf}}
}

// A brute force, the login that followed and what was done in that session are
// one story with a reason and the highest severity reached.
func TestAttackIsOneIncident(t *testing.T) {
	r := &rig{t: t}
	for i := 0; i < 5; i++ {
		r.feed(Input{Event: r.ev(time.Duration(i)*time.Second, model.KindSSHLoginFail, model.SevWarn, "198.51.100.7", nil)})
	}
	if len(r.st.Items) != 0 {
		t.Fatalf("failures alone must not open an incident: %+v", r.st.Items)
	}
	r.feed(Input{Event: r.ev(6*time.Second, model.KindSSHLoginFail, model.SevWarn, "198.51.100.7", nil), Banned: []Ban{{IP: "198.51.100.7", Reason: "6 failed logins within 10m"}}})
	r.feed(Input{Event: r.ev(20*time.Second, model.KindLoginAfterBruteForce, model.SevCritical, "198.51.100.7", nil)})
	r.feed(Input{Event: r.ev(40*time.Second, model.KindSSHLoginOK, model.SevCritical, "198.51.100.7", nil)})
	r.feed(Input{Event: r.ev(60*time.Second, model.KindSudo, model.SevInfo, "", session("198.51.100.7", model.ConfObserved))})
	r.feed(Input{Event: r.ev(70*time.Second, model.KindAuthorizedKeysChange, model.SevCritical, "", session("198.51.100.7", model.ConfObserved))})

	open := r.open()
	if len(open) != 1 {
		t.Fatalf("want one incident, got %d: %+v", len(open), open)
	}
	in := open[0]
	if in.ReasonKey != "incident.reason.bruteforce_ban" || in.SrcIP != "198.51.100.7" || in.State != New || in.Severity != model.SevCritical {
		t.Errorf("%+v", in)
	}
	if in.Kinds["sudo"] != 1 || in.Kinds["authorized_keys_change"] != 1 || in.Kinds["login_after_bruteforce"] != 1 || len(in.Bans) != 1 {
		t.Errorf("story is incomplete: kinds=%v bans=%v", in.Kinds, in.Bans)
	}
	var viaSession int
	for _, e := range in.Events {
		if e.Via == "session" {
			viaSession++
		}
	}
	if viaSession != 2 {
		t.Errorf("the two session actions must be linked through the observed session: %+v", in.Events)
	}
}

// Only an observed address links an action to an address's incident. A
// correlated or unknown session, or the same user name, does not.
func TestWeakAttributionDoesNotLink(t *testing.T) {
	r := &rig{t: t}
	r.feed(Input{Event: r.ev(0, model.KindLoginAfterBruteForce, model.SevCritical, "198.51.100.7", nil)})
	for _, conf := range []string{model.ConfCorrelated, model.ConfUnknown} {
		r.feed(Input{Event: r.ev(10*time.Second, model.KindUserChange, model.SevCritical, "", session("198.51.100.7", conf))})
	}
	if got := r.st.Items["inc-1"]; got.Total != 1 {
		t.Errorf("a weakly attributed action was linked to the address incident: %+v", got)
	}
	// Each becomes its own session-keyed story, not part of the address's.
	if len(r.open()) != 2 {
		t.Errorf("want the address incident and one session incident, got %d", len(r.open()))
	}
}

func TestSeparateAddressesAndGaps(t *testing.T) {
	r := &rig{t: t}
	r.feed(Input{Event: r.ev(0, model.KindLoginAfterBruteForce, model.SevCritical, "198.51.100.7", nil)})
	r.feed(Input{Event: r.ev(time.Second, model.KindLoginAfterBruteForce, model.SevCritical, "203.0.113.9", nil)})
	if len(r.open()) != 2 {
		t.Fatalf("two addresses, two incidents: %d", len(r.open()))
	}
	// After a long silence the same address is a new story.
	r.feed(Input{Event: r.ev(3*time.Hour, model.KindLoginAfterBruteForce, model.SevCritical, "198.51.100.7", nil)})
	if len(r.st.Items) != 3 {
		t.Errorf("a new story after the gap: %d", len(r.st.Items))
	}
}

func TestStatesEscalationAndResolved(t *testing.T) {
	r := &rig{t: t}
	r.feed(Input{Event: r.ev(0, model.KindSSHLoginOK, model.SevWarn, "198.51.100.7", nil), Banned: []Ban{{IP: "198.51.100.7"}}})
	in := r.st.Items["inc-1"]
	ack, ok := SetState(in, Acknowledged, "panel", t0)
	if !ok {
		t.Fatal("ack")
	}
	r.st.Items[ack.ID] = ack
	if _, again := SetState(ack, Acknowledged, "panel", t0); again {
		t.Error("no change must report no change")
	}
	// Routine activity keeps it acknowledged; something worse brings it back.
	r.feed(Input{Event: r.ev(time.Minute, model.KindSSHLoginFail, model.SevWarn, "198.51.100.7", nil)})
	if r.st.Items["inc-1"].State != Acknowledged {
		t.Error("routine activity must not reopen an acknowledged incident")
	}
	r.feed(Input{Event: r.ev(2*time.Minute, model.KindLoginAfterBruteForce, model.SevCritical, "198.51.100.7", nil)})
	if got := r.st.Items["inc-1"]; got.State != New || len(got.Notes) < 2 {
		t.Errorf("escalation must reopen it, with a note: %+v", got)
	}
	// Resolved is closed: the next trigger is a new incident.
	res, _ := SetState(r.st.Items["inc-1"], Resolved, "tg:1", t0.Add(time.Hour))
	r.st.Items[res.ID] = res
	r.feed(Input{Event: r.ev(3*time.Minute, model.KindLoginAfterBruteForce, model.SevCritical, "198.51.100.7", nil)})
	if len(r.st.Items) != 2 || r.st.Items["inc-1"].Total != res.Total {
		t.Errorf("a resolved incident must not absorb new activity: %+v", r.st.Items)
	}
}

// Feeding the very same event again changes nothing.
func TestSameEventTwiceIsIdempotent(t *testing.T) {
	r := &rig{t: t}
	e := r.ev(0, model.KindLoginAfterBruteForce, model.SevCritical, "198.51.100.7", nil)
	r.feed(Input{Event: e})
	r.feed(Input{Event: e})
	if in := r.st.Items["inc-1"]; len(r.st.Items) != 1 || in.Total != 1 {
		t.Errorf("%+v", r.st.Items)
	}
}

// Plan never modifies the state it is given: that is what lets the store roll
// back a failed write.
func TestPlanDoesNotMutate(t *testing.T) {
	r := &rig{t: t}
	r.feed(Input{Event: r.ev(0, model.KindLoginAfterBruteForce, model.SevCritical, "198.51.100.7", nil)})
	before := *r.st.Items["inc-1"]
	Plan(&r.st, Input{Event: r.ev(time.Second, model.KindSSHLoginOK, model.SevCritical, "198.51.100.7", nil)})
	if r.st.Items["inc-1"].Total != before.Total || len(r.st.Items["inc-1"].Events) != len(before.Events) {
		t.Error("Plan changed the stored incident")
	}
}

func TestBounds(t *testing.T) {
	r := &rig{t: t}
	r.feed(Input{Event: r.ev(0, model.KindLoginAfterBruteForce, model.SevCritical, "198.51.100.7", nil)})
	for i := 1; i < 200; i++ {
		r.feed(Input{Event: r.ev(time.Duration(i)*time.Second, model.KindSSHLoginFail, model.SevWarn, "198.51.100.7", nil)})
	}
	in := r.st.Items["inc-1"]
	if len(in.Events) != MaxEvents || in.Total != 200 {
		t.Errorf("events=%d total=%d", len(in.Events), in.Total)
	}

	// Many incidents: resolved ones go first and the set stays bounded.
	r = &rig{t: t}
	for i := 0; i < MaxIncidents+50; i++ {
		ip := fmt.Sprintf("10.%d.%d.1", i/250, i%250)
		r.feed(Input{Event: r.ev(time.Duration(i)*time.Second, model.KindLoginAfterBruteForce, model.SevCritical, ip, nil)})
		if i%2 == 0 {
			id := fmt.Sprintf("inc-%d", i+1)
			if res, ok := SetState(r.st.Items[id], Resolved, "x", t0.Add(time.Duration(i)*time.Second)); ok {
				r.st.Items[id] = res
			}
		}
	}
	if len(r.st.Items) > MaxIncidents {
		t.Errorf("%d incidents exceed the bound", len(r.st.Items))
	}
	open := 0
	for _, in := range r.st.Items {
		if in.State != Resolved {
			open++
		}
	}
	if open < MaxIncidents/2 {
		t.Errorf("open incidents were dropped before resolved ones: %d", open)
	}
}

func TestResolvedExpire(t *testing.T) {
	r := &rig{t: t}
	r.feed(Input{Event: r.ev(0, model.KindLoginAfterBruteForce, model.SevCritical, "198.51.100.7", nil)})
	res, _ := SetState(r.st.Items["inc-1"], Resolved, "x", t0)
	r.st.Items["inc-1"] = res
	ch := r.feed(Input{Event: r.ev(ResolvedKeep+time.Hour, model.KindLoginAfterBruteForce, model.SevCritical, "203.0.113.9", nil)})
	if len(ch.Drop) != 1 || ch.Drop[0] != "inc-1" {
		t.Errorf("an expired resolved incident should be dropped: %+v", ch.Drop)
	}
}
