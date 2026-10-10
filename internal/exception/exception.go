// Package exception holds the owner's targeted exceptions: "this expected
// activity is not worth a notification".
//
// An exception only silences the notification and the incident of events that
// match it exactly. The event is still journaled, shown in the panel with the
// exception that muted it, and counted. It never affects detection or bans, and
// it never silences a critical event. It always has a reason and an expiry, and
// it must name something narrower than a whole kind.
package exception

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/netaddr"
)

// Limits.
const (
	MaxRules   = 200
	MaxField   = 200
	MaxReason  = 200
	MaxLife    = 90 * 24 * time.Hour
	KeepExpiry = 7 * 24 * time.Hour // expired rules stay visible this long
)

// Rule is one exception. Every non-empty match field must match (AND).
type Rule struct {
	ID         string     `json:"id"`
	Kind       model.Kind `json:"kind"` // required: there is no catch-all
	User       string     `json:"user,omitempty"`
	LoginUser  string     `json:"login_user,omitempty"`
	SrcIP      string     `json:"src_ip,omitempty"` // an address or a CIDR network
	PathPrefix string     `json:"path_prefix,omitempty"`
	CmdPrefix  string     `json:"cmd_prefix,omitempty"`
	Exe        string     `json:"exe,omitempty"`
	Reason     string     `json:"reason"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid exception")

func clean(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) > MaxField {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}

// Validate checks and normalizes a new rule. now is the creation time.
func Validate(r Rule, now time.Time) (Rule, error) {
	bad := func(format string, a ...any) (Rule, error) {
		return Rule{}, fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
	}
	if !model.ValidKind(r.Kind) {
		return bad("unknown kind %q", r.Kind)
	}
	var ok bool
	for _, f := range []*string{&r.User, &r.LoginUser, &r.SrcIP, &r.PathPrefix, &r.CmdPrefix, &r.Exe} {
		if *f, ok = clean(*f); !ok {
			return bad("a field is too long or has control characters")
		}
	}
	if r.User == "" && r.LoginUser == "" && r.SrcIP == "" && r.PathPrefix == "" && r.CmdPrefix == "" && r.Exe == "" {
		return bad("name something narrower than the whole kind (user, address, path, command or program)")
	}
	if r.SrcIP != "" {
		e, err := netaddr.ParseEntry(r.SrcIP)
		if err != nil {
			return bad("src_ip: %v", err)
		}
		r.SrcIP = e.String()
	}
	if r.Reason, ok = clean(r.Reason); !ok || r.Reason == "" || len(r.Reason) > MaxReason {
		return bad("a reason is required (up to %d characters)", MaxReason)
	}
	if r.ExpiresAt.IsZero() || !r.ExpiresAt.After(now) {
		return bad("an expiry in the future is required")
	}
	if r.ExpiresAt.After(now.Add(MaxLife)) {
		return bad("the longest exception is %d days", int(MaxLife/(24*time.Hour)))
	}
	r.CreatedAt = now
	return r, nil
}

// Active reports whether the rule is in force at t.
func (r Rule) Active(t time.Time) bool { return t.Before(r.ExpiresAt) }

// Matches reports whether the rule silences the event. Critical events are
// never silenced, whatever the rule says.
func (r Rule) Matches(ev model.Event, now time.Time) bool {
	if !r.Active(now) || ev.Severity >= model.SevCritical || ev.Kind != r.Kind {
		return false
	}
	if r.User != "" && ev.User != r.User {
		return false
	}
	if r.LoginUser != "" && (ev.Context == nil || ev.Context.LoginUser != r.LoginUser) {
		return false
	}
	if r.Exe != "" && (ev.Context == nil || ev.Context.Exe != r.Exe) {
		return false
	}
	if r.PathPrefix != "" && !strings.HasPrefix(ev.Arg("path"), r.PathPrefix) {
		return false
	}
	if r.CmdPrefix != "" && !strings.HasPrefix(ev.Arg("cmd"), r.CmdPrefix) {
		return false
	}
	if r.SrcIP != "" {
		e, err := netaddr.ParseEntry(r.SrcIP)
		if err != nil {
			return false
		}
		a, err := netaddr.Parse(ev.SrcIP)
		if err != nil || !e.Contains(a) {
			return false
		}
	}
	return true
}
