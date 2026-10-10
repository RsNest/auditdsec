package decision

import (
	"context"
	"errors"
	"time"

	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/netaddr"
	"github.com/RsNest/auditdsec/internal/store"
)

// Proposal is a ban the detector wants because of one journaled event.
type Proposal struct {
	IP     string
	Reason string
	Until  time.Time
}

// Committed is what became of one proposal.
type Committed struct {
	Proposal
	Ban        store.Ban
	Created    bool     // a new decision was recorded
	Refused    *Refusal // the policy or the allowlist turned it down
	EnforceErr error    // the firewall failed; the decision stands and is retried
}

// CommitDetection is the one way detection results become decisions. The
// proposals that pass the policy and the progress cursor are written in a
// single atomic state write (store.CommitDetection): either the desired
// decisions, their notification duty and the cursor past the event are all
// durable, or none is and the event is offered again. Only after that write
// are the new decisions enforced, outside the commit, so a firewall that is
// slow, broken or killed with the process cannot undo or block it; the
// reconciler enforces what the commit left pending.
//
// A proposal for an address that already has an active ban changes nothing
// (no new offence, no extended ban). One for an address the policy or the
// allowlist protects is refused. Both still let the cursor move.
func (s *Service) CommitDetection(ctx context.Context, pos delivery.Position, props []Proposal) ([]Committed, error) {
	out := make([]Committed, len(props))
	var accepted []store.DetectBan
	var index []int
	for i, p := range props {
		out[i].Proposal = p
		a, err := netaddr.Parse(p.IP)
		if err != nil {
			out[i].Refused = &Refusal{Reason: ReasonInvalid, Detail: err.Error()}
			continue
		}
		key := a.String()
		out[i].IP = key
		if ref := s.check(a); ref != nil {
			out[i].Refused = ref
			continue
		}
		if !p.Until.IsZero() && !p.Until.After(s.now()) {
			out[i].Refused = &Refusal{Reason: ReasonOver}
			continue
		}
		accepted = append(accepted, store.DetectBan{IP: key, Reason: p.Reason, Until: p.Until})
		index = append(index, i)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	results, err := s.opt.Store.CommitDetection(pos, accepted)
	if err != nil {
		return nil, err
	}
	// results is nil when the position was already committed; nothing is owed.
	for n, r := range results {
		i := index[n]
		switch {
		case errors.Is(r.Err, store.ErrAllowlisted):
			out[i].Refused = &Refusal{Reason: ReasonAllowlisted}
		case r.Err != nil:
			out[i].Refused = &Refusal{Reason: ReasonInvalid, Detail: r.Err.Error()}
		default:
			out[i].Ban, out[i].Created = r.Ban, r.Created
		}
	}
	actor := Actor{Origin: FromDetector}
	for i := range out {
		c := &out[i]
		switch {
		case c.Refused != nil:
			s.record(actor, "ban", c.IP, "refused:"+c.Refused.Error(), "")
		case c.Created:
			c.Ban, c.EnforceErr = s.enforceLocked(ctx, c.Ban)
			outcome := "ok"
			if c.EnforceErr != nil {
				outcome = "recorded; firewall failed"
			}
			s.record(actor, "ban", c.IP, outcome, c.Ban.State)
		}
	}
	return out, nil
}
