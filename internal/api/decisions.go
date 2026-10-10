package api

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/decision"
	"github.com/RsNest/auditdsec/internal/netaddr"
	"github.com/RsNest/auditdsec/internal/store"
)

// enforcerBanner lets the panel's narrow Enforcer stand in for a banner when
// no shared decision service was given (tests). It cannot list.
type enforcerBanner struct{ Enforcer }

func (enforcerBanner) List(context.Context) ([]action.Decision, error) { return nil, nil }
func (enforcerBanner) Name() string                                    { return "enforcer" }

func (s *Server) decisions() *decision.Service { return s.opt.Decisions }

var durations = map[string]time.Duration{
	"1h": time.Hour, "24h": 24 * time.Hour, "30d": 30 * 24 * time.Hour, "permanent": 0,
}

func cleanReason(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
		if b.Len() >= 200 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// parseIP accepts only a plain address and returns its canonical form.
func parseIP(v string) (netip.Addr, bool) {
	a, err := netaddr.Parse(v)
	return a, err == nil
}

func (s *Server) actor(r *http.Request) decision.Actor {
	return decision.Actor{Origin: decision.FromPanel, Who: s.clientIP(r)}
}

// refuse answers a policy refusal and reports whether err was one.
func refuse(w http.ResponseWriter, err error) bool {
	ref, ok := decision.IsRefusal(err)
	if !ok {
		return false
	}
	switch ref.Reason {
	case decision.ReasonInvalid:
		fail(w, http.StatusBadRequest, "bad_ip", "not an address")
	case decision.ReasonNotBannable:
		fail(w, http.StatusBadRequest, "bad_ip", "not a bannable address ("+string(ref.Class)+")")
	case decision.ReasonSelf:
		fail(w, http.StatusConflict, "self", "that is your own address; banning it would lock you out")
	case decision.ReasonAllowlisted:
		fail(w, http.StatusConflict, "allowlisted", "the address is on the allowlist")
	case decision.ReasonOver:
		fail(w, http.StatusBadRequest, "bad_duration", "that ban would already have ended")
	default:
		fail(w, http.StatusBadRequest, "bad_request", ref.Error())
	}
	return true
}

func (s *Server) handleBan(w http.ResponseWriter, r *http.Request) {
	var in struct{ IP, Duration, Reason string }
	if !decode(w, r, &in) {
		return
	}
	d, ok := durations[in.Duration]
	if !ok {
		fail(w, http.StatusBadRequest, "bad_duration", "duration must be 1h, 24h, 30d or permanent")
		return
	}
	var until time.Time
	if d > 0 {
		until = s.now().Add(d)
	}
	reason := "manual ban from the panel"
	if extra := cleanReason(in.Reason); extra != "" {
		reason += ": " + extra
	}
	res, err := s.decisions().Ban(r.Context(), decision.BanRequest{
		IP: in.IP, Until: until, Reason: reason, Actor: s.actor(r), Protect: []string{s.clientIP(r)},
	})
	if err != nil {
		if refuse(w, err) {
			return
		}
		s.log.Error("cannot record the ban", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "cannot record the ban")
		return
	}
	s.log.Info("panel: ban", "ip", res.Ban.IP, "until", until, "by", s.clientIP(r), "state", res.Ban.State)
	if res.EnforceErr != nil {
		fail(w, http.StatusBadGateway, "firewall", "the decision was recorded, but the firewall refused the ban")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		banJSON
		AlreadyBanned bool `json:"already_banned"`
	}{toBanJSON(res.Ban), !res.Created})
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	res, err := s.decisions().Unban(r.Context(), r.PathValue("ip"), s.actor(r))
	if err != nil {
		if refuse(w, err) {
			return
		}
		s.log.Warn("cannot lift the ban", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "cannot save")
		return
	}
	s.log.Info("panel: unban", "ip", r.PathValue("ip"), "by", s.clientIP(r), "pending", res.Pending)
	if res.Pending {
		// Accepted, not done: the record is removed, the block is still in
		// the firewall until a retry succeeds.
		writeJSON(w, http.StatusAccepted, map[string]any{
			"removed": res.Removed, "pending": true, "error": clipText(res.Err),
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAllow(w http.ResponseWriter, r *http.Request) {
	var in struct{ IP string }
	if !decode(w, r, &in) {
		return
	}
	res, err := s.decisions().Allow(r.Context(), in.IP, "added from the panel", s.actor(r))
	if err != nil {
		if refuse(w, err) {
			return
		}
		fail(w, http.StatusInternalServerError, "internal", "cannot save")
		return
	}
	s.log.Info("panel: allow", "entry", res.Key, "by", s.clientIP(r), "pending", len(res.Pending))
	out := map[string]any{"ip": res.Key, "added": s.now().UTC(), "source": "manual", "removed_bans": len(res.Removed)}
	if len(res.Pending) > 0 {
		out["unblock_pending"] = res.Pending
		out["error"] = clipText(res.Err)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUnallow(w http.ResponseWriter, r *http.Request) {
	if _, err := s.decisions().Unallow(r.PathValue("ip"), s.actor(r)); err != nil {
		if refuse(w, err) {
			return
		}
		fail(w, http.StatusInternalServerError, "internal", "cannot save")
		return
	}
	s.log.Info("panel: unallow", "entry", r.PathValue("ip"), "by", s.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func clipText(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// banJSON is a ban as the panel sees it. Applied is true only when the
// firewall is known to hold the block; State says what is known otherwise.
type banJSON struct {
	IP          string     `json:"ip"`
	Reason      string     `json:"reason"`
	Created     time.Time  `json:"created"`
	Until       *time.Time `json:"until"`
	Permanent   bool       `json:"permanent"`
	RepeatCount int        `json:"repeat_count"`
	Applied     bool       `json:"applied"`
	Source      string     `json:"source"`
	State       string     `json:"state"`
	Backend     string     `json:"backend,omitempty"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

func toBanJSON(b store.Ban) banJSON {
	state := b.State
	if state == "" {
		state = store.StatePending
	}
	out := banJSON{
		IP: b.IP, Reason: b.Reason, Created: b.CreatedAt.UTC(), Permanent: b.Permanent(),
		RepeatCount: b.Count, Applied: state == store.StateApplied, Source: "auto",
		State: state, Backend: b.Backend, LastError: b.LastError,
	}
	if !b.Permanent() {
		u := b.Until.UTC()
		out.Until = &u
	}
	if !b.VerifiedAt.IsZero() {
		v := b.VerifiedAt.UTC()
		out.VerifiedAt = &v
	}
	if strings.HasPrefix(b.Reason, "manual") {
		out.Source = "manual"
	}
	return out
}

func (s *Server) activeBans() []banJSON {
	now := s.now()
	out := []banJSON{}
	for _, b := range s.opt.Store.Bans() {
		if b.Active(now) {
			out = append(out, toBanJSON(b))
		}
	}
	return out
}
