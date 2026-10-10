package decision

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/store"
)

// fakeFW is a firewall the test controls.
type fakeFW struct {
	mu        sync.Mutex
	elems     map[string]time.Time // zero: permanent
	failBan   error
	failUnban error
	failList  error
	bans      int
	unbans    int
	dry       bool
}

func newFW() *fakeFW { return &fakeFW{elems: map[string]time.Time{}} }

func (f *fakeFW) Ban(_ context.Context, d action.Decision) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bans++
	if f.failBan != nil {
		return f.failBan
	}
	if !f.dry {
		f.elems[d.IP] = d.Until
	}
	return nil
}

func (f *fakeFW) Unban(_ context.Context, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unbans++
	if f.failUnban != nil {
		return f.failUnban
	}
	delete(f.elems, ip)
	return nil
}

func (f *fakeFW) List(context.Context) ([]action.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList != nil {
		return nil, f.failList
	}
	var out []action.Decision
	for ip, u := range f.elems {
		out = append(out, action.Decision{IP: ip, Until: u})
	}
	return out, nil
}

func (f *fakeFW) Name() string { return "fake" }
func (f *fakeFW) DryRun() bool { return f.dry }

func setup(t *testing.T, fw action.Banner, mod func(*Options)) (*Service, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(store.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	o := Options{Store: st, Banner: fw, Actions: &ActionLog{Path: filepath.Join(dir, "actions.jsonl")}}
	if mod != nil {
		mod(&o)
	}
	return New(o), st, dir
}

var ctx = context.Background()
var panelUser = Actor{Origin: FromPanel, Who: "198.51.100.200"}

func hour() time.Time { return time.Now().Add(time.Hour) }

func TestBanIsEnforcedAndRecordedAsApplied(t *testing.T) {
	fw := newFW()
	s, _, _ := setup(t, fw, nil)
	res, err := s.Ban(ctx, BanRequest{IP: "203.0.113.7", Until: hour(), Reason: "x", Actor: panelUser})
	if err != nil || !res.Created || res.EnforceErr != nil {
		t.Fatalf("%+v %v", res, err)
	}
	b := res.Ban
	if b.State != store.StateApplied || !b.Applied || b.Backend != "fake" || b.VerifiedAt.IsZero() {
		t.Errorf("%+v", b)
	}
	if _, ok := fw.elems["203.0.113.7"]; !ok {
		t.Error("the firewall holds nothing")
	}
}

// One policy for every interface.
func TestPolicyRefusals(t *testing.T) {
	s, st, _ := setup(t, newFW(), nil)
	cases := map[string]string{
		"127.0.0.1":       ReasonNotBannable,
		"::1":             ReasonNotBannable,
		"0.0.0.0":         ReasonNotBannable,
		"224.0.0.1":       ReasonNotBannable,
		"169.254.1.1":     ReasonNotBannable,
		"fe80::1":         ReasonNotBannable,
		"10.0.0.5":        ReasonNotBannable,
		"192.168.1.9":     ReasonNotBannable,
		"fd00::1":         ReasonNotBannable,
		"::ffff:10.1.1.1": ReasonNotBannable,
		"not-an-ip":       ReasonInvalid,
		"":                ReasonInvalid,
	}
	for ip, want := range cases {
		_, err := s.Ban(ctx, BanRequest{IP: ip, Until: hour(), Actor: panelUser})
		if r, ok := IsRefusal(err); !ok || r.Reason != want {
			t.Errorf("%q: %v, want %s", ip, err, want)
		}
	}
	if len(st.Bans()) != 0 {
		t.Error("a refused ban left a record")
	}
	// the requester's own address, in another spelling
	_, err := s.Ban(ctx, BanRequest{IP: "2001:db8::1", Until: hour(), Protect: []string{"2001:DB8:0:0:0:0:0:1"}, Actor: panelUser})
	if r, ok := IsRefusal(err); !ok || r.Reason != ReasonSelf {
		t.Errorf("self: %v", err)
	}
	// already over
	_, err = s.Ban(ctx, BanRequest{IP: "203.0.113.9", Until: time.Now().Add(-time.Minute), Actor: panelUser})
	if r, ok := IsRefusal(err); !ok || r.Reason != ReasonOver {
		t.Errorf("over: %v", err)
	}
}

func TestPrivateNetworksOnlyByExplicitSetting(t *testing.T) {
	s, _, _ := setup(t, newFW(), func(o *Options) { o.BanPrivate = true })
	if _, err := s.Ban(ctx, BanRequest{IP: "10.0.0.5", Until: hour(), Actor: panelUser}); err != nil {
		t.Errorf("private with the setting: %v", err)
	}
	// loopback and friends are never bannable
	if _, err := s.Ban(ctx, BanRequest{IP: "127.0.0.1", Until: hour(), Actor: panelUser}); err == nil {
		t.Error("loopback was banned")
	}
}

func TestAllowlistProtectsEverySpellingAndNetwork(t *testing.T) {
	s, _, _ := setup(t, newFW(), nil)
	if _, err := s.Allow(ctx, "203.0.113.0/24", "office", panelUser); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.50", "::ffff:203.0.113.50"} {
		_, err := s.Ban(ctx, BanRequest{IP: ip, Until: hour(), Actor: Actor{Origin: FromDetector}})
		if r, ok := IsRefusal(err); !ok || r.Reason != ReasonAllowlisted {
			t.Errorf("%s: %v", ip, err)
		}
	}
	if _, err := s.Allow(ctx, "0.0.0.0/0", "", panelUser); err == nil {
		t.Error("a network that covers everything was accepted")
	}
}

// An active ban is not another offence; another spelling is not another address.
func TestActiveBanIsIdempotentAcrossInterfaces(t *testing.T) {
	fw := newFW()
	s, st, _ := setup(t, fw, nil)
	var wg sync.WaitGroup
	results := make([]BanResult, 6)
	spell := []string{"2001:db8::7", "2001:DB8:0:0:0:0:0:7", "2001:db8:0::7", "2001:db8::7", "2001:0db8::0007", "2001:db8::7"}
	origins := []Origin{FromDetector, FromTelegram, FromPanel, FromDetector, FromTelegram, FromPanel}
	for i := range spell {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := s.Ban(ctx, BanRequest{IP: spell[i], Until: hour(), Reason: "r", Actor: Actor{Origin: origins[i]}})
			if err != nil {
				t.Error(err)
			}
			results[i] = r
		}(i)
	}
	wg.Wait()
	created := 0
	for _, r := range results {
		if r.Created {
			created++
		}
	}
	b, _ := st.Ban("2001:db8::7")
	if created != 1 || b.Count != 1 || len(st.Bans()) != 1 {
		t.Errorf("created %d, count %d, records %d", created, b.Count, len(st.Bans()))
	}
}

func TestStatesAreTruthfulWithoutAFirewall(t *testing.T) {
	// no backend
	s, _, _ := setup(t, nil, nil)
	res, _ := s.Ban(ctx, BanRequest{IP: "203.0.113.7", Until: hour(), Actor: panelUser})
	if res.Ban.State != store.StateUnknown || res.Ban.Applied || res.Ban.Backend != "none" {
		t.Errorf("no backend must not read as blocked: %+v", res.Ban)
	}
	// the no-op banner is the same
	s, _, _ = setup(t, action.NoopBanner{}, nil)
	res, _ = s.Ban(ctx, BanRequest{IP: "203.0.113.7", Until: hour(), Actor: panelUser})
	if res.Ban.State != store.StateUnknown || res.Ban.Applied {
		t.Errorf("noop: %+v", res.Ban)
	}
	// dry run
	fw := newFW()
	fw.dry = true
	s, _, _ = setup(t, fw, nil)
	res, _ = s.Ban(ctx, BanRequest{IP: "203.0.113.7", Until: hour(), Actor: panelUser})
	if res.Ban.State != store.StateDryRun || res.Ban.Applied || len(fw.elems) != 0 {
		t.Errorf("dry run must not read as blocked: %+v", res.Ban)
	}
}

func TestFirewallFailureIsRecordedAndRetried(t *testing.T) {
	fw := newFW()
	fw.failBan = errors.New("nft: Operation not permitted")
	s, st, _ := setup(t, fw, nil)
	res, err := s.Ban(ctx, BanRequest{IP: "203.0.113.7", Until: hour(), Reason: "r", Actor: panelUser})
	if err != nil || res.EnforceErr == nil || res.Ban.State != store.StateFailed || res.Ban.Applied || !strings.Contains(res.Ban.LastError, "not permitted") {
		t.Fatalf("%+v %v", res, err)
	}
	// the owner presses again after fixing the problem: same decision, no new offence
	fw.failBan = nil
	res, err = s.Ban(ctx, BanRequest{IP: "203.0.113.7", Until: hour(), Reason: "other", Actor: panelUser})
	if err != nil || res.Created || res.Ban.State != store.StateApplied || res.Ban.Count != 1 || res.Ban.Reason != "r" {
		t.Fatalf("%+v %v", res, err)
	}
	if b, _ := st.Ban("203.0.113.7"); b.LastError != "" {
		t.Errorf("the error should be cleared: %+v", b)
	}
}

func TestUnbanFailureStaysOnRecordAndIsRetried(t *testing.T) {
	fw := newFW()
	s, st, _ := setup(t, fw, nil)
	s.Ban(ctx, BanRequest{IP: "203.0.113.7", Until: hour(), Actor: panelUser})
	fw.failUnban = errors.New("busy")
	res, err := s.Unban(ctx, "203.0.113.7", panelUser)
	if err != nil || !res.Removed || !res.Pending || res.Err == nil {
		t.Fatalf("%+v %v", res, err)
	}
	if rel := st.Releases(); len(rel) != 1 || rel[0].LastError != "busy" {
		t.Fatalf("the unblock must stay on record: %+v", rel)
	}
	if _, ok := fw.elems["203.0.113.7"]; !ok {
		t.Fatal("setup: the element should still be there")
	}
	fw.failUnban = nil
	rep := s.Reconcile(ctx)
	if rep.Released != 1 || len(st.Releases()) != 0 || len(fw.elems) != 0 {
		t.Errorf("%+v %+v %v", rep, st.Releases(), fw.elems)
	}
}

// "Trusted" is the owner's decision and holds even when the firewall cannot
// lift the block yet; the answer says the unblock is not complete.
func TestAllowWithFailingFirewall(t *testing.T) {
	fw := newFW()
	s, st, _ := setup(t, fw, nil)
	s.Ban(ctx, BanRequest{IP: "203.0.113.7", Until: hour(), Actor: panelUser})
	fw.failUnban = errors.New("busy")
	res, err := s.Allow(ctx, "203.0.113.7", "me", panelUser)
	if err != nil || len(res.Removed) != 1 || len(res.Pending) != 1 || res.Pending[0] != "203.0.113.7" {
		t.Fatalf("%+v %v", res, err)
	}
	if !s.Allowed("203.0.113.7") {
		t.Error("the address must be trusted")
	}
	if _, ok := st.Ban("203.0.113.7"); ok {
		t.Error("the ban record should be gone")
	}
	fw.failUnban = nil
	s.Reconcile(ctx)
	if len(fw.elems) != 0 || len(st.Releases()) != 0 {
		t.Errorf("not completed: %v %v", fw.elems, st.Releases())
	}
}

func TestReconcileRepairsTheFirewall(t *testing.T) {
	fw := newFW()
	s, st, _ := setup(t, fw, nil)
	s.Ban(ctx, BanRequest{IP: "203.0.113.1", Until: hour(), Actor: panelUser})                         // will be lost
	s.Ban(ctx, BanRequest{IP: "203.0.113.2", Until: time.Now().Add(48 * time.Hour), Actor: panelUser}) // wrong timeout
	s.Ban(ctx, BanRequest{IP: "203.0.113.3", Until: hour(), Actor: panelUser})                         // fine
	s.Ban(ctx, BanRequest{IP: "203.0.113.4", Actor: panelUser})                                        // permanent, fine

	delete(fw.elems, "203.0.113.1")                       // an external reload dropped it
	fw.elems["203.0.113.2"] = time.Now().Add(time.Minute) // timeout not renewed
	fw.elems["203.0.113.99"] = time.Time{}                // nobody asked for this
	fw.bans = 0

	rep := s.Reconcile(ctx)
	if rep.Checked != 4 || rep.Reapplied != 1 || rep.Renewed != 1 || rep.Orphans != 1 || rep.Failed != 0 {
		t.Fatalf("%+v", rep)
	}
	if _, ok := fw.elems["203.0.113.1"]; !ok {
		t.Error("the lost block was not put back")
	}
	if u := fw.elems["203.0.113.2"]; u.Before(time.Now().Add(47 * time.Hour)) {
		t.Errorf("the timeout was not renewed: %v", u)
	}
	if _, ok := fw.elems["203.0.113.99"]; ok {
		t.Error("the orphan stayed")
	}
	if fw.bans != 2 {
		t.Errorf("only the two differing blocks are re-enforced, got %d Ban calls", fw.bans)
	}
	// and it converges: nothing to do the second time
	fw.bans = 0
	if rep := s.Reconcile(ctx); rep.Reapplied+rep.Renewed+rep.Orphans+rep.Failed != 0 || fw.bans != 0 {
		t.Errorf("not idempotent: %+v, %d calls", rep, fw.bans)
	}
	if b, _ := st.Ban("203.0.113.1"); b.State != store.StateApplied {
		t.Errorf("%+v", b)
	}
}

func TestReconcileWhenTheFirewallCannotBeRead(t *testing.T) {
	fw := newFW()
	s, st, _ := setup(t, fw, nil)
	s.Ban(ctx, BanRequest{IP: "203.0.113.1", Until: hour(), Actor: panelUser})
	fw.failList = errors.New("nft gone")
	fw.bans = 0
	rep := s.Reconcile(ctx)
	if rep.ListErr == nil || fw.bans != 0 || fw.unbans != 0 {
		t.Errorf("an unreadable firewall must change nothing: %+v", rep)
	}
	if b, _ := st.Ban("203.0.113.1"); b.State != store.StateApplied {
		t.Errorf("state was invented: %+v", b)
	}
}

func TestReconcileMarksExpiredAndAdoptsStates(t *testing.T) {
	now := time.Now()
	clock := &now
	fw := newFW()
	s, st, _ := setup(t, fw, func(o *Options) { o.Now = func() time.Time { return *clock } })
	s.Ban(ctx, BanRequest{IP: "203.0.113.1", Until: now.Add(time.Hour), Actor: panelUser})
	later := now.Add(2 * time.Hour)
	clock = &later
	rep := s.Reconcile(ctx)
	if b, _ := st.Ban("203.0.113.1"); rep.Expired != 1 || b.State != store.StateExpired {
		t.Errorf("%+v %+v", rep, b)
	}
	// a record that says pending (or failed) is adopted as applied once the
	// firewall is seen to hold it
	s2, st2, _ := setup(t, fw, nil)
	b, _, _ := st2.EnsureBan("203.0.113.5", "x", hour())
	fw.elems["203.0.113.5"] = b.Until
	s2.Reconcile(ctx)
	if got, _ := st2.Ban("203.0.113.5"); got.State != store.StateApplied {
		t.Errorf("%+v", got)
	}
}

func TestOperatorActionsAreJournaled(t *testing.T) {
	s, _, dir := setup(t, newFW(), nil)
	s.Ban(ctx, BanRequest{IP: "203.0.113.7", Until: hour(), Actor: Actor{Origin: FromPanel, Who: "198.51.100.200"}})
	s.Ban(ctx, BanRequest{IP: "10.0.0.1", Until: hour(), Actor: Actor{Origin: FromTelegram, Who: "42"}})
	s.Unban(ctx, "203.0.113.7", Actor{Origin: FromTelegram, Who: "42"})
	b, err := os.ReadFile(filepath.Join(dir, "actions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines:\n%s", len(lines), b)
	}
	var last Action
	json.Unmarshal([]byte(lines[2]), &last)
	if last.Origin != FromTelegram || last.Who != "42" || last.Action != "unban" || last.Outcome != "ok" || last.Target != "203.0.113.7" {
		t.Errorf("%+v", last)
	}
	var refused Action
	json.Unmarshal([]byte(lines[1]), &refused)
	if !strings.HasPrefix(refused.Outcome, "refused:not_bannable") {
		t.Errorf("%+v", refused)
	}
}

func TestDueNoticesSurviveUntilCleared(t *testing.T) {
	s, st, dir := setup(t, newFW(), nil)
	s.Ban(ctx, BanRequest{IP: "203.0.113.7", Until: hour(), Actor: Actor{Origin: FromDetector}, NoticeDue: true})
	s.Ban(ctx, BanRequest{IP: "203.0.113.8", Until: hour(), Actor: panelUser})
	st.Close()
	st2, _ := store.Open(store.Options{Dir: dir})
	defer st2.Close()
	s2 := New(Options{Store: st2})
	due := s2.DueNotices()
	if len(due) != 1 || due[0].IP != "203.0.113.7" {
		t.Fatalf("after a restart: %+v", due)
	}
	if err := s2.NoticeSent("203.0.113.7"); err != nil || len(s2.DueNotices()) != 0 {
		t.Errorf("not cleared")
	}
}
