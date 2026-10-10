// Package decision is the one place where an address is banned, unbanned,
// trusted or released. The detector, the Telegram bot and the web panel used to
// each check addresses, call the firewall and write the store in their own
// way; they now ask this service, so the same address gets the same answer
// whoever asks, and what the firewall is known to hold is recorded the same
// way.
//
// What a decision wants is in the store: while a ban is active the address
// should be blocked; a Release is an address whose block must be lifted. What
// has been seen of the firewall is the ban's State. The Reconciler compares
// the two with what the backend reports and repairs the difference, so a
// reload of the firewall, a lost rule or a failed unban does not stay hidden.
//
// Dry-run and "no backend" are states of their own: nothing here ever reports
// a block that was not made.
package decision

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/netaddr"
	"github.com/RsNest/auditdsec/internal/store"
)

// Origin names the interface a request came through.
type Origin string

const (
	FromDetector Origin = "detector"
	FromTelegram Origin = "telegram"
	FromPanel    Origin = "panel"
	FromSystem   Origin = "system" // startup, the reconciler, automatic allowlisting
)

// Actor is who asked: the interface and, where known, the person (the client
// address of a panel session, the Telegram chat).
type Actor struct {
	Origin Origin
	Who    string
}

// Reasons a request is refused. They are stable slugs.
const (
	ReasonInvalid     = "invalid_address"
	ReasonNotBannable = "not_bannable"
	ReasonAllowlisted = "allowlisted"
	ReasonSelf        = "self"
	ReasonOver        = "already_over"
)

// Refusal is a request the policy turns down. It is an answer, not a failure.
type Refusal struct {
	Reason string
	Class  netaddr.Class // for ReasonNotBannable
	Detail string
}

func (r *Refusal) Error() string {
	if r.Class != "" {
		return fmt.Sprintf("%s (%s)", r.Reason, r.Class)
	}
	if r.Detail != "" {
		return r.Reason + ": " + r.Detail
	}
	return r.Reason
}

// IsRefusal reports whether err is a policy refusal, and which.
func IsRefusal(err error) (*Refusal, bool) {
	var r *Refusal
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}

// Options configures a Service.
type Options struct {
	Store  *store.Store
	Banner action.Banner // nil: nothing enforces
	// BanPrivate allows banning private-network addresses. Off by default: a
	// VPS reaches its own network through them. Detection of an intruder
	// inside the private network is not affected, only the block.
	BanPrivate bool
	Log        *slog.Logger
	Now        func() time.Time
	Actions    *ActionLog
}

// Service serializes every decision, whoever asks.
type Service struct {
	opt Options
	log *slog.Logger
	now func() time.Time

	mu sync.Mutex
}

// New returns a Service.
func New(o Options) *Service {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{opt: o, log: o.Log, now: o.Now}
}

// Mode says whether the backend really blocks, only logs, or is absent.
func (s *Service) Mode() action.Mode { return action.ModeOf(s.opt.Banner) }

// Backend names the backend for the records ("none" when there is none).
func (s *Service) Backend() string {
	if s.Mode() == action.ModeNone || s.opt.Banner == nil {
		return "none"
	}
	return s.opt.Banner.Name()
}

// check applies the one policy about which addresses may be blocked.
func (s *Service) check(a netip.Addr) *Refusal {
	switch c := netaddr.Classify(a); c {
	case netaddr.Public:
		return nil
	case netaddr.Private:
		if s.opt.BanPrivate {
			return nil
		}
		return &Refusal{Reason: ReasonNotBannable, Class: c}
	default:
		return &Refusal{Reason: ReasonNotBannable, Class: c}
	}
}

// BanRequest asks for an address to be blocked.
type BanRequest struct {
	IP     string
	Until  time.Time // zero: permanent
	Reason string
	Actor  Actor
	// Protect lists addresses that must not be banned by this request, such as
	// the requester's own: banning it would lock them out.
	Protect []string
	// NoticeDue records, with the decision, that its notification is owed.
	NoticeDue bool
}

// BanResult is the outcome of a ban request.
type BanResult struct {
	Ban     store.Ban
	Created bool // false: an active ban already existed and was kept
	// EnforceErr is why the firewall refused, if it did. The decision is
	// recorded either way and the reconciler keeps retrying.
	EnforceErr error
}

// Ban records a ban and enforces it. An active ban is not another offence:
// its reason, expiry and repeat count are kept, and enforcement is retried if
// it is not confirmed.
func (s *Service) Ban(ctx context.Context, req BanRequest) (BanResult, error) {
	a, err := netaddr.Parse(req.IP)
	if err != nil {
		s.record(req.Actor, "ban", req.IP, "refused:"+ReasonInvalid, "")
		return BanResult{}, &Refusal{Reason: ReasonInvalid, Detail: err.Error()}
	}
	key := a.String()
	if ref := s.check(a); ref != nil {
		s.record(req.Actor, "ban", key, "refused:"+ref.Error(), "")
		return BanResult{}, ref
	}
	for _, p := range req.Protect {
		if pa, err := netaddr.Parse(p); err == nil && pa == a {
			s.record(req.Actor, "ban", key, "refused:"+ReasonSelf, "")
			return BanResult{}, &Refusal{Reason: ReasonSelf}
		}
	}
	if !req.Until.IsZero() && !req.Until.After(s.now()) {
		s.record(req.Actor, "ban", key, "refused:"+ReasonOver, "")
		return BanResult{}, &Refusal{Reason: ReasonOver}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	b, created, err := s.opt.Store.EnsureBanWith(key, req.Reason, req.Until,
		store.BanOptions{Origin: string(req.Actor.Origin), NoticeDue: req.NoticeDue})
	if errors.Is(err, store.ErrAllowlisted) {
		s.record(req.Actor, "ban", key, "refused:"+ReasonAllowlisted, "")
		return BanResult{}, &Refusal{Reason: ReasonAllowlisted}
	}
	if err != nil {
		s.record(req.Actor, "ban", key, "failed", err.Error())
		return BanResult{}, err
	}
	res := BanResult{Ban: b, Created: created}
	if created || b.State != store.StateApplied {
		res.Ban, res.EnforceErr = s.enforceLocked(ctx, b)
	}
	outcome := "ok"
	if res.EnforceErr != nil {
		outcome = "recorded; firewall failed"
	} else if !created {
		outcome = "already banned"
	}
	s.record(req.Actor, "ban", key, outcome, res.Ban.State)
	return res, nil
}

// enforceLocked applies one ban to the backend and records what happened. It
// never claims a block that was not made.
func (s *Service) enforceLocked(ctx context.Context, b store.Ban) (store.Ban, error) {
	backend := s.Backend()
	now := s.now()
	if !b.Active(now) {
		nb, _, err := s.opt.Store.UpdateBan(b.IP, func(x *store.Ban) { x.State, x.Backend = store.StateExpired, backend })
		if err != nil {
			return b, err
		}
		return nb, nil
	}
	var state, lastErr string
	var enforceErr error
	switch s.Mode() {
	case action.ModeNone:
		state = store.StateUnknown
	case action.ModeDryRun:
		state = store.StateDryRun
		_ = s.opt.Banner.Ban(ctx, action.Decision{IP: b.IP, Until: b.Until, Reason: b.Reason}) // logs the command
	default:
		if err := s.opt.Banner.Ban(ctx, action.Decision{IP: b.IP, Until: b.Until, Reason: b.Reason}); err != nil {
			state, enforceErr = store.StateFailed, err
			lastErr = clip(err.Error())
			s.log.Error("the firewall refused the ban", "ip", b.IP, "error", err)
		} else {
			state = store.StateApplied
		}
	}
	nb, _, err := s.opt.Store.UpdateBan(b.IP, func(x *store.Ban) {
		x.State, x.Backend, x.LastError = state, backend, lastErr
		x.Attempts++
		if state == store.StateApplied {
			x.VerifiedAt = now
		}
	})
	if err != nil {
		s.log.Error("cannot save the enforcement state of a ban", "ip", b.IP, "error", err)
		if enforceErr == nil {
			enforceErr = err
		}
		return b, enforceErr
	}
	return nb, enforceErr
}

// UnbanResult is the outcome of an unban request.
type UnbanResult struct {
	Removed bool  // a ban record existed
	Pending bool  // the firewall has not confirmed the unblock; it will be retried
	Err     error // why, when Pending
}

// Unban removes a ban record and lifts the block. The removal and the duty to
// lift the block are one write: if the firewall refuses, the address stays on
// the release list and is retried, and the answer says so.
func (s *Service) Unban(ctx context.Context, ip string, actor Actor) (UnbanResult, error) {
	a, err := netaddr.Parse(ip)
	if err != nil {
		s.record(actor, "unban", ip, "refused:"+ReasonInvalid, "")
		return UnbanResult{}, &Refusal{Reason: ReasonInvalid, Detail: err.Error()}
	}
	key := a.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed, err := s.opt.Store.Unban(key)
	if err != nil {
		s.record(actor, "unban", key, "failed", err.Error())
		return UnbanResult{}, err
	}
	res := UnbanResult{Removed: removed}
	res.Err = s.liftLocked(ctx, key)
	res.Pending = res.Err != nil
	switch {
	case res.Pending:
		s.record(actor, "unban", key, "pending", res.Err.Error())
	case removed:
		s.record(actor, "unban", key, "ok", "")
	default:
		s.record(actor, "unban", key, "nothing to remove", "")
	}
	return res, nil
}

// liftLocked asks the backend to unblock an address and settles the Release
// record. Without a real backend there is nothing to lift: the record is
// cleared, since nothing blocks.
func (s *Service) liftLocked(ctx context.Context, key string) error {
	if s.Mode() != action.ModeEnforcing {
		if s.Mode() == action.ModeDryRun {
			_ = s.opt.Banner.Unban(ctx, key)
		}
		return s.opt.Store.UpdateRelease(key, nil)
	}
	err := s.opt.Banner.Unban(ctx, key)
	if err != nil {
		s.log.Error("the firewall refused the unban", "ip", key, "error", err)
	}
	if serr := s.opt.Store.UpdateRelease(key, err); serr != nil && err == nil {
		return serr
	}
	return err
}

// AllowResult is the outcome of an allow request.
type AllowResult struct {
	Key     string      // canonical entry
	Removed []store.Ban // bans that the entry removed
	Pending []string    // addresses whose unblock the firewall has not confirmed
	Err     error       // the first such error
}

// Allow trusts an address or a CIDR network and removes the bans it covers.
// Trusting is the owner's decision and is kept even when the firewall cannot
// lift a block right now: the answer then says "trusted, unblock not
// completed", and the block is retried.
func (s *Service) Allow(ctx context.Context, entry, note string, actor Actor) (AllowResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, removed, err := s.opt.Store.AllowEntry(entry, note)
	if err != nil {
		if errors.Is(err, store.ErrInvalidAddress) {
			s.record(actor, "allow", entry, "refused:"+ReasonInvalid, err.Error())
			return AllowResult{}, &Refusal{Reason: ReasonInvalid, Detail: err.Error()}
		}
		s.record(actor, "allow", entry, "failed", err.Error())
		return AllowResult{}, err
	}
	res := AllowResult{Key: key, Removed: removed}
	targets := map[string]bool{}
	for _, b := range removed {
		targets[b.IP] = true
	}
	// A single address is lifted even if no ban record existed: the firewall
	// may still hold an element that the records forgot.
	if en, err := netaddr.ParseEntry(key); err == nil && !en.IsNetwork() {
		targets[en.Addr.String()] = true
	}
	for ip := range targets {
		if lerr := s.liftLocked(ctx, ip); lerr != nil {
			res.Pending = append(res.Pending, ip)
			if res.Err == nil {
				res.Err = lerr
			}
		}
	}
	outcome := "ok"
	if len(res.Pending) > 0 {
		outcome = "trusted; unblock pending"
	}
	s.record(actor, "allow", key, outcome, "")
	return res, nil
}

// Unallow removes an allowlist entry.
func (s *Service) Unallow(entry string, actor Actor) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed, err := s.opt.Store.Unallow(entry)
	if err != nil {
		if errors.Is(err, store.ErrInvalidAddress) {
			s.record(actor, "unallow", entry, "refused:"+ReasonInvalid, "")
			return false, &Refusal{Reason: ReasonInvalid, Detail: err.Error()}
		}
		s.record(actor, "unallow", entry, "failed", err.Error())
		return false, err
	}
	s.record(actor, "unallow", entry, map[bool]string{true: "ok", false: "not on the list"}[removed], "")
	return removed, nil
}

// Allowed reports whether an address is trusted.
func (s *Service) Allowed(ip string) bool { return s.opt.Store.IsAllowed(ip) }

// Reapply enforces every active ban once, as the first step after start. It
// is a Reconcile: what the firewall already holds is left alone.
func (s *Service) Reapply(ctx context.Context) Report { return s.Reconcile(ctx) }

func (s *Service) record(actor Actor, action, target, outcome, detail string) {
	if s.opt.Actions == nil {
		return
	}
	s.opt.Actions.Append(Action{Time: s.now().UTC(), Origin: actor.Origin, Who: actor.Who,
		Action: action, Target: target, Outcome: outcome, Detail: detail})
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
