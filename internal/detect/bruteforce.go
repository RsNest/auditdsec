package detect

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/model"
)

// Ladder is how long a ban lasts by how many times the address has been banned
// before. Past the end of the ladder the ban is permanent.
//
// It starts at an hour on purpose. Addresses are shared and recycled: carrier
// NAT, office gateways, a phone that changes networks. A first offence that
// cost the owner their own access forever would make the agent worse than the
// attack, so "forever" is reserved for an address that keeps coming back.
var Ladder = []time.Duration{
	time.Hour,
	24 * time.Hour,
	30 * 24 * time.Hour,
}

// EscalateFrom returns when a ban should expire, given how many times the
// address was banned before. A zero time means permanent.
func EscalateFrom(now time.Time, prior int) time.Time {
	if prior < 0 {
		prior = 0
	}
	if prior >= len(Ladder) {
		return time.Time{}
	}
	return now.Add(Ladder[prior])
}

// Options configures the brute-force detector.
type Options struct {
	// Window is how far back failures are counted.
	Window time.Duration
	// FailThreshold is how many failures inside the window trigger a ban.
	FailThreshold int
	// SuccessAfterFailures is how many recent failures make a later success
	// from the same address suspicious. Zero disables that signal.
	SuccessAfterFailures int
	// BanCount reports how many times an address has already been banned, so
	// the ladder can escalate. Supplied by the store; nil means no escalation.
	BanCount func(ip string) int
	// Allowed reports whether an address must never be banned. Supplied by the
	// store's allowlist; nil means nothing is protected.
	Allowed func(ip string) bool
	// MaxTracked caps how many addresses are remembered, so a spray across
	// many sources cannot grow the agent's memory without bound.
	MaxTracked int
	// Host is stamped onto the events the detector produces.
	Host string
}

// BruteForce counts failed logins per source address over a sliding window.
//
// The event's own timestamp is the clock, not time.Now(), so replaying a log
// produces exactly the same decisions as watching it live — which is what
// makes the thresholds testable.
type BruteForce struct {
	opt Options

	mu      sync.Mutex
	seen    map[string]*tracker
	lastHit map[string]time.Time
}

type tracker struct {
	fails    []time.Time
	bannedAt time.Time
}

// NewBruteForce returns a detector with sane defaults for a small VPS.
func NewBruteForce(o Options) *BruteForce {
	if o.Window <= 0 {
		o.Window = 10 * time.Minute
	}
	if o.FailThreshold <= 0 {
		o.FailThreshold = 10
	}
	if o.MaxTracked <= 0 {
		o.MaxTracked = 10000
	}
	return &BruteForce{
		opt:     o,
		seen:    make(map[string]*tracker),
		lastHit: make(map[string]time.Time),
	}
}

// Name identifies the detector in logs and in /status.
func (d *BruteForce) Name() string { return "brute-force" }

// Feed consumes one event and reports what it triggered.
func (d *BruteForce) Feed(ev model.Event) Result {
	ip := ev.SrcIP
	if !bannable(ip) {
		return Result{}
	}

	switch ev.Kind {
	case model.KindSSHLoginFail:
		return d.onFailure(ev, ip)
	case model.KindSSHLoginOK:
		return d.onSuccess(ev, ip)
	default:
		return Result{}
	}
}

func (d *BruteForce) onFailure(ev model.Event, ip string) Result {
	now := ev.Time
	if now.IsZero() {
		now = time.Now()
	}

	d.mu.Lock()
	t := d.track(ip, now)
	t.fails = append(prune(t.fails, now.Add(-d.opt.Window)), now)
	count := len(t.fails)
	banned := !t.bannedAt.IsZero() && now.Sub(t.bannedAt) < d.opt.Window
	if count >= d.opt.FailThreshold && !banned {
		t.bannedAt = now
		t.fails = nil
	} else {
		count = 0 // not a decision point
	}
	d.mu.Unlock()

	if count == 0 {
		return Result{}
	}

	// The allowlist is checked here as well as in the store: refusing early
	// keeps a protected address out of the logs and out of the chat, instead
	// of announcing a ban that is then silently refused.
	if d.opt.Allowed != nil && d.opt.Allowed(ip) {
		return Result{}
	}

	prior := 0
	if d.opt.BanCount != nil {
		prior = d.opt.BanCount(ip)
	}
	return Result{Decisions: []action.Decision{{
		IP:     ip,
		Until:  EscalateFrom(now, prior),
		Reason: fmt.Sprintf("%d failed logins within %s", count, humanWindow(d.opt.Window)),
	}}}
}

// onSuccess reports the signal that matters most: a login that worked right
// after a burst that did not. That is what a guessed password looks like.
func (d *BruteForce) onSuccess(ev model.Event, ip string) Result {
	if d.opt.SuccessAfterFailures <= 0 {
		return Result{}
	}
	now := ev.Time
	if now.IsZero() {
		now = time.Now()
	}

	d.mu.Lock()
	t, ok := d.seen[ip]
	fails := 0
	if ok {
		t.fails = prune(t.fails, now.Add(-d.opt.Window))
		fails = len(t.fails)
		if fails >= d.opt.SuccessAfterFailures {
			// Reported once: the owner does not need it again for every
			// command in the session that follows.
			t.fails = nil
		}
	}
	d.mu.Unlock()

	if fails < d.opt.SuccessAfterFailures {
		return Result{}
	}

	host := ev.Host
	if host == "" {
		host = d.opt.Host
	}
	return Result{Events: []model.Event{{
		Time:       now,
		Host:       host,
		Kind:       model.KindLoginAfterBruteForce,
		Severity:   model.SevCritical,
		User:       ev.User,
		SrcIP:      ip,
		SummaryKey: "event." + string(model.KindLoginAfterBruteForce),
		Args: map[string]string{
			"user":  ev.User,
			"ip":    ip,
			"fails": fmt.Sprintf("%d", fails),
			"kind":  string(model.KindLoginAfterBruteForce),
		},
		Raw: ev.Raw,
	}}}
}

// track returns the tracker for an address, evicting the least recently seen
// one when the table is full.
func (d *BruteForce) track(ip string, now time.Time) *tracker {
	if t, ok := d.seen[ip]; ok {
		d.lastHit[ip] = now
		return t
	}
	if len(d.seen) >= d.opt.MaxTracked {
		d.evictOldest()
	}
	t := &tracker{}
	d.seen[ip] = t
	d.lastHit[ip] = now
	return t
}

func (d *BruteForce) evictOldest() {
	var oldest string
	var at time.Time
	for ip, t := range d.lastHit {
		if oldest == "" || t.Before(at) {
			oldest, at = ip, t
		}
	}
	if oldest != "" {
		delete(d.seen, oldest)
		delete(d.lastHit, oldest)
	}
}

// Tracked reports how many addresses are being watched, for /debug.
func (d *BruteForce) Tracked() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}

// Failures reports the current count for an address, for tests and /debug.
func (d *BruteForce) Failures(ip string, now time.Time) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.seen[ip]
	if !ok {
		return 0
	}
	return len(prune(t.fails, now.Add(-d.opt.Window)))
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	keep := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	return keep
}

// bannable rejects the addresses it would be pointless or dangerous to block:
// anything that is not an address at all, loopback, link-local, and the private
// ranges a VPS reaches its own network through.
func bannable(s string) bool {
	if s == "" {
		return false
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !ip.IsLoopback() && !ip.IsUnspecified() &&
		!ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

func humanWindow(d time.Duration) string {
	s := d.Round(time.Second).String()
	if len(s) > 2 && s[len(s)-3:] == "m0s" {
		s = s[:len(s)-2]
	}
	if len(s) > 2 && s[len(s)-3:] == "h0m" {
		s = s[:len(s)-2]
	}
	return s
}
