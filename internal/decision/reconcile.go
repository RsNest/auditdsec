package decision

import (
	"context"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/netaddr"
	"github.com/RsNest/auditdsec/internal/store"
)

const (
	// A block is "the same" when the firewall's remaining time is within this
	// of the decision's: the listing is rounded and takes time to read.
	timeoutTolerance = 30 * time.Second
	// Verification is written back at most this often per ban, so a quiet
	// system does not rewrite its state file every cycle.
	verifyEvery = 10 * time.Minute
)

// Report says what one reconciliation found and did.
type Report struct {
	Checked   int   // active bans compared with the firewall
	Reapplied int   // blocks that were missing and have been put back
	Renewed   int   // blocks whose timeout differed and has been renewed
	Released  int   // pending unblocks that now succeeded
	Orphans   int   // blocks the records do not want, removed
	Expired   int   // bans that ran out
	Failed    int   // operations that failed and will be retried
	ListErr   error // the firewall could not be read: nothing was verified
}

// Reconcile compares what the records want with what the backend reports, and
// repairs the difference. It is safe to call at any time and idempotent; it
// never replays a completed enforcement, because it acts on the difference
// only.
func (s *Service) Reconcile(ctx context.Context) Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	var rep Report
	now := s.now()
	mode := s.Mode()

	// 1. Unblocks the owner asked for and the firewall has not confirmed.
	for _, r := range s.opt.Store.Releases() {
		if err := s.liftLocked(ctx, r.IP); err != nil {
			rep.Failed++
		} else {
			rep.Released++
			s.record(Actor{Origin: FromSystem}, "unblock", r.IP, "ok (retry)", "")
		}
	}

	// 2. Bans that ran out.
	bans := s.opt.Store.Bans()
	active := map[string]store.Ban{}
	for _, b := range bans {
		if b.Active(now) {
			active[b.IP] = b
			continue
		}
		if b.State != store.StateExpired {
			if _, _, err := s.opt.Store.UpdateBan(b.IP, func(x *store.Ban) { x.State = store.StateExpired }); err == nil {
				rep.Expired++
			}
		}
	}

	// 3. Without a real backend there is nothing to compare: record the truth
	// about each active ban.
	if mode != action.ModeEnforcing {
		want := store.StateUnknown
		if mode == action.ModeDryRun {
			want = store.StateDryRun
		}
		for _, b := range active {
			if b.State != want || b.Backend != s.Backend() {
				_, _, _ = s.opt.Store.UpdateBan(b.IP, func(x *store.Ban) {
					x.State, x.Backend, x.LastError = want, s.Backend(), ""
				})
			}
		}
		return rep
	}

	// 4. Compare with the firewall.
	listed, err := s.opt.Banner.List(ctx)
	if err != nil {
		rep.ListErr = err
		s.log.Warn("cannot read the firewall; nothing was verified", "error", err)
		return rep
	}
	actual := map[string]action.Decision{}
	for _, d := range listed {
		if c, err := netaddr.Canon(d.IP); err == nil {
			d.IP = c
			actual[c] = d
		}
	}

	for ip, b := range active {
		rep.Checked++
		cur, present := actual[ip]
		switch {
		case !present:
			nb, err := s.enforceLocked(ctx, b)
			if err != nil || nb.State != store.StateApplied {
				rep.Failed++
				s.log.Warn("a ban is missing from the firewall and could not be put back", "ip", ip, "error", err)
			} else {
				rep.Reapplied++
				s.log.Warn("a ban was missing from the firewall; it has been put back", "ip", ip)
				s.record(Actor{Origin: FromSystem}, "reapply", ip, "ok", "was missing")
			}
		case timeoutDiffers(b, cur):
			nb, err := s.enforceLocked(ctx, b)
			if err != nil || nb.State != store.StateApplied {
				rep.Failed++
			} else {
				rep.Renewed++
				s.log.Info("the firewall's timeout did not match the decision; renewed", "ip", ip)
				s.record(Actor{Origin: FromSystem}, "renew", ip, "ok", "timeout differed")
			}
		case b.State != store.StateApplied || now.Sub(b.VerifiedAt) >= verifyEvery:
			_, _, _ = s.opt.Store.UpdateBan(ip, func(x *store.Ban) {
				x.State, x.Backend, x.LastError, x.VerifiedAt = store.StateApplied, s.Backend(), "", now
			})
		}
	}

	// 5. Blocks nobody wants: a failed unban, a reload that kept an old set,
	// an allowlist entry added while the firewall was out of reach. The table
	// is the agent's own, so these are removed.
	for ip := range actual {
		if _, want := active[ip]; want {
			continue
		}
		if err := s.opt.Banner.Unban(ctx, ip); err != nil {
			rep.Failed++
			s.log.Warn("cannot remove a block that no decision wants", "ip", ip, "error", err)
			continue
		}
		rep.Orphans++
		s.log.Warn("removed a block that no decision wants", "ip", ip)
		s.record(Actor{Origin: FromSystem}, "unblock", ip, "ok", "no decision wanted it")
	}
	return rep
}

// timeoutDiffers reports whether the firewall's element has a different end
// than the decision: a permanent block that has a timeout, a timed block that
// has none, or times that disagree by more than the tolerance.
func timeoutDiffers(b store.Ban, cur action.Decision) bool {
	if b.Permanent() != cur.Permanent() {
		return true
	}
	if b.Permanent() {
		return false
	}
	d := b.Until.Sub(cur.Until)
	if d < 0 {
		d = -d
	}
	return d > timeoutTolerance
}

// Run reconciles now and then every interval until ctx ends. after, if set,
// is called with each report.
func (s *Service) Run(ctx context.Context, every time.Duration, after func(Report)) {
	if every <= 0 {
		every = 2 * time.Minute
	}
	rep := s.Reconcile(ctx)
	if after != nil {
		after(rep)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rep := s.Reconcile(ctx)
			if after != nil {
				after(rep)
			}
		}
	}
}

// DueNotices returns the active automatic bans whose notification is still
// owed, oldest first.
func (s *Service) DueNotices() []store.Ban {
	var out []store.Ban
	now := s.now()
	bans := s.opt.Store.Bans()
	for i := len(bans) - 1; i >= 0; i-- {
		if b := bans[i]; b.NoticeDue && b.Active(now) {
			out = append(out, b)
		}
	}
	return out
}

// NoticeSent records that a ban's notification reached the outbox.
func (s *Service) NoticeSent(ip string) error { return s.opt.Store.ClearNotice(ip) }
