package detect

import (
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
)

var base = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func fail(ip string, at time.Time) model.Event {
	return model.Event{Time: at, Host: "web01", Kind: model.KindSSHLoginFail,
		Severity: model.SevWarn, User: "root", SrcIP: ip}
}

func ok(ip string, at time.Time) model.Event {
	return model.Event{Time: at, Host: "web01", Kind: model.KindSSHLoginOK,
		Severity: model.SevInfo, User: "root", SrcIP: ip}
}

func TestBruteForceBansAtTheThreshold(t *testing.T) {
	d := NewBruteForce(Options{Window: 10 * time.Minute, FailThreshold: 5})

	for i := 0; i < 4; i++ {
		if r := d.Feed(fail("198.51.100.7", base.Add(time.Duration(i)*time.Second))); !r.Empty() {
			t.Fatalf("failure %d should not trigger anything: %+v", i+1, r)
		}
	}
	r := d.Feed(fail("198.51.100.7", base.Add(5*time.Second)))
	if len(r.Decisions) != 1 {
		t.Fatalf("the fifth failure should trigger a ban, got %+v", r)
	}
	dec := r.Decisions[0]
	if dec.IP != "198.51.100.7" {
		t.Errorf("IP = %q", dec.IP)
	}
	if dec.Reason == "" {
		t.Error("the decision should carry a reason")
	}
	if dec.Permanent() {
		t.Error("a first offence must not be permanent")
	}
	if want := base.Add(5*time.Second + time.Hour); !dec.Until.Equal(want) {
		t.Errorf("Until = %v, want %v (first rung of the ladder)", dec.Until, want)
	}
}

// Failures older than the window must not count, or a slow scan over days
// would eventually trip a threshold meant for a burst.
func TestBruteForceWindowSlides(t *testing.T) {
	d := NewBruteForce(Options{Window: time.Minute, FailThreshold: 3})

	d.Feed(fail("203.0.113.5", base))
	d.Feed(fail("203.0.113.5", base.Add(10*time.Second)))
	if r := d.Feed(fail("203.0.113.5", base.Add(2*time.Minute))); !r.Empty() {
		t.Fatalf("the first two failures fell out of the window: %+v", r)
	}
	if got := d.Failures("203.0.113.5", base.Add(2*time.Minute)); got != 1 {
		t.Errorf("Failures = %d, want 1", got)
	}
}

func TestBruteForceCountsPerAddress(t *testing.T) {
	d := NewBruteForce(Options{Window: 10 * time.Minute, FailThreshold: 3})
	for i := 0; i < 2; i++ {
		d.Feed(fail("198.51.100.1", base))
		d.Feed(fail("198.51.100.2", base))
	}
	if r := d.Feed(fail("198.51.100.1", base)); len(r.Decisions) != 1 {
		t.Fatalf("the third failure from .1 should ban it: %+v", r)
	}
	if r := d.Feed(fail("198.51.100.2", base)); len(r.Decisions) != 1 {
		t.Fatalf("the third failure from .2 should ban it too: %+v", r)
	}
}

// After a ban the counter restarts, so the same burst cannot ban the same
// address on every subsequent packet.
func TestBruteForceDoesNotRepeatWithinTheWindow(t *testing.T) {
	d := NewBruteForce(Options{Window: 10 * time.Minute, FailThreshold: 2})
	d.Feed(fail("198.51.100.7", base))
	if r := d.Feed(fail("198.51.100.7", base.Add(time.Second))); len(r.Decisions) != 1 {
		t.Fatal("expected the first ban")
	}
	for i := 0; i < 20; i++ {
		if r := d.Feed(fail("198.51.100.7", base.Add(time.Duration(2+i)*time.Second))); !r.Empty() {
			t.Fatalf("attempt %d banned again inside the window: %+v", i, r)
		}
	}
	// Once the window has passed, a fresh burst bans again.
	later := base.Add(11 * time.Minute)
	d.Feed(fail("198.51.100.7", later))
	if r := d.Feed(fail("198.51.100.7", later.Add(time.Second))); len(r.Decisions) != 1 {
		t.Fatalf("a new burst should ban again: %+v", r)
	}
}

func TestBruteForceEscalates(t *testing.T) {
	prior := 0
	d := NewBruteForce(Options{
		Window: time.Minute, FailThreshold: 1,
		BanCount: func(string) int { return prior },
	})

	tests := []struct {
		priorBans int
		want      time.Duration
		permanent bool
	}{
		{0, time.Hour, false},
		{1, 24 * time.Hour, false},
		{2, 30 * 24 * time.Hour, false},
		{3, 0, true},
		{9, 0, true},
	}
	for i, tc := range tests {
		prior = tc.priorBans
		at := base.Add(time.Duration(i) * time.Hour) // a fresh window each time
		r := d.Feed(fail("198.51.100.9", at))
		if len(r.Decisions) != 1 {
			t.Fatalf("prior=%d: no decision", tc.priorBans)
		}
		dec := r.Decisions[0]
		if tc.permanent {
			if !dec.Permanent() {
				t.Errorf("prior=%d: want permanent, got until %v", tc.priorBans, dec.Until)
			}
			continue
		}
		if !dec.Until.Equal(at.Add(tc.want)) {
			t.Errorf("prior=%d: Until = %v, want %v", tc.priorBans, dec.Until, at.Add(tc.want))
		}
	}
}

// The allowlist is what stops the agent locking its owner out, so it must be
// honoured before a ban is ever announced.
func TestBruteForceRespectsTheAllowlist(t *testing.T) {
	d := NewBruteForce(Options{
		Window: time.Minute, FailThreshold: 2,
		Allowed: func(ip string) bool { return ip == "203.0.113.9" },
	})
	d.Feed(fail("203.0.113.9", base))
	if r := d.Feed(fail("203.0.113.9", base.Add(time.Second))); !r.Empty() {
		t.Errorf("an allowlisted address must never be banned: %+v", r)
	}
	d.Feed(fail("198.51.100.7", base))
	if r := d.Feed(fail("198.51.100.7", base.Add(time.Second))); len(r.Decisions) != 1 {
		t.Error("other addresses are still banned")
	}
}

// Private and loopback addresses are how a host reaches its own network, and
// blocking them would cut the agent off from the machine it protects.
func TestBruteForceIgnoresUnbannableAddresses(t *testing.T) {
	d := NewBruteForce(Options{Window: time.Minute, FailThreshold: 2})
	for _, ip := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9", "169.254.1.1", "::1", "", "not-an-ip"} {
		for i := 0; i < 5; i++ {
			if r := d.Feed(fail(ip, base.Add(time.Duration(i)*time.Second))); !r.Empty() {
				t.Errorf("address %q should never be banned: %+v", ip, r)
			}
		}
	}
	if d.Tracked() != 0 {
		t.Errorf("Tracked = %d, want 0", d.Tracked())
	}
}

// The signal that matters most: the password was eventually guessed.
func TestBruteForceReportsSuccessAfterFailures(t *testing.T) {
	d := NewBruteForce(Options{
		Window: 10 * time.Minute, FailThreshold: 100, // high, so no ban interferes
		SuccessAfterFailures: 5,
		Host:                 "web01",
	})
	for i := 0; i < 5; i++ {
		d.Feed(fail("198.51.100.7", base.Add(time.Duration(i)*time.Second)))
	}
	r := d.Feed(ok("198.51.100.7", base.Add(10*time.Second)))
	if len(r.Events) != 1 {
		t.Fatalf("expected a derived event, got %+v", r)
	}
	ev := r.Events[0]
	if ev.Kind != model.KindLoginAfterBruteForce {
		t.Errorf("Kind = %q", ev.Kind)
	}
	if ev.Severity != model.SevCritical {
		t.Errorf("Severity = %v, want critical", ev.Severity)
	}
	if ev.Arg("fails") != "5" || ev.SrcIP != "198.51.100.7" || ev.Host != "web01" {
		t.Errorf("event = %+v", ev)
	}

	// Reported once, not for every record of the session that follows.
	if r := d.Feed(ok("198.51.100.7", base.Add(11*time.Second))); !r.Empty() {
		t.Errorf("the signal should not repeat: %+v", r)
	}
}

func TestBruteForceIgnoresCleanLogin(t *testing.T) {
	d := NewBruteForce(Options{Window: 10 * time.Minute, SuccessAfterFailures: 5})
	for i := 0; i < 4; i++ { // below the threshold: a typo, not an attack
		d.Feed(fail("198.51.100.7", base.Add(time.Duration(i)*time.Second)))
	}
	if r := d.Feed(ok("198.51.100.7", base.Add(5*time.Second))); !r.Empty() {
		t.Errorf("four failures and a login is somebody mistyping: %+v", r)
	}
}

func TestBruteForceSuccessSignalCanBeDisabled(t *testing.T) {
	d := NewBruteForce(Options{Window: time.Minute, SuccessAfterFailures: 0})
	for i := 0; i < 50; i++ {
		d.Feed(fail("198.51.100.7", base.Add(time.Duration(i)*time.Millisecond)))
	}
	if r := d.Feed(ok("198.51.100.7", base.Add(time.Second))); len(r.Events) != 0 {
		t.Errorf("the signal is off, got %+v", r)
	}
}

func TestBruteForceIgnoresOtherKinds(t *testing.T) {
	d := NewBruteForce(Options{Window: time.Minute, FailThreshold: 1})
	ev := model.Event{Time: base, Kind: model.KindSudo, SrcIP: "198.51.100.7"}
	if r := d.Feed(ev); !r.Empty() {
		t.Errorf("sudo is not a login failure: %+v", r)
	}
}

// A spray from thousands of sources must not grow memory without bound.
func TestBruteForceEvictsWhenFull(t *testing.T) {
	d := NewBruteForce(Options{Window: time.Hour, FailThreshold: 100, MaxTracked: 10})
	for i := 0; i < 50; i++ {
		ip := "198.51.100." + itoa(i%250+1)
		d.Feed(fail(ip, base.Add(time.Duration(i)*time.Second)))
	}
	if got := d.Tracked(); got > 10 {
		t.Errorf("Tracked = %d, want at most 10", got)
	}
}

func TestEscalateFrom(t *testing.T) {
	if got := EscalateFrom(base, -1); !got.Equal(base.Add(time.Hour)) {
		t.Errorf("a negative count should behave like zero: %v", got)
	}
	if got := EscalateFrom(base, len(Ladder)); !got.IsZero() {
		t.Errorf("past the ladder should be permanent: %v", got)
	}
}

func TestName(t *testing.T) {
	if NewBruteForce(Options{}).Name() == "" {
		t.Error("a detector needs a name for the logs")
	}
}

// NewBruteForce must be usable with an empty Options.
func TestDefaults(t *testing.T) {
	d := NewBruteForce(Options{})
	if d.opt.Window <= 0 || d.opt.FailThreshold <= 0 || d.opt.MaxTracked <= 0 {
		t.Errorf("defaults are not sane: %+v", d.opt)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

var _ Detector = (*BruteForce)(nil)
