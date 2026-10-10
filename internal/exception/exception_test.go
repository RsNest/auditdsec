package exception

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func rule(mod func(*Rule)) Rule {
	r := Rule{Kind: model.KindSudo, User: "root", CmdPrefix: "systemctl restart nginx", Reason: "nightly deploy", ExpiresAt: now.Add(24 * time.Hour)}
	if mod != nil {
		mod(&r)
	}
	return r
}

func TestValidate(t *testing.T) {
	if _, err := Validate(rule(nil), now); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Rule){
		"unknown kind":          func(r *Rule) { r.Kind = "nope" },
		"whole kind":            func(r *Rule) { r.User, r.CmdPrefix = "", "" },
		"no reason":             func(r *Rule) { r.Reason = " " },
		"no expiry":             func(r *Rule) { r.ExpiresAt = time.Time{} },
		"past expiry":           func(r *Rule) { r.ExpiresAt = now.Add(-time.Minute) },
		"too long":              func(r *Rule) { r.ExpiresAt = now.Add(MaxLife + time.Hour) },
		"bad address":           func(r *Rule) { r.SrcIP = "not an ip" },
		"control characters":    func(r *Rule) { r.CmdPrefix = "a\x00b" },
		"field too long":        func(r *Rule) { r.PathPrefix = strings.Repeat("a", MaxField+1) },
		"reason with a newline": func(r *Rule) { r.Reason = "x\ny" },
	}
	for name, mod := range bad {
		if _, err := Validate(rule(mod), now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	got, _ := Validate(rule(func(r *Rule) { r.SrcIP = "::ffff:203.0.113.5" }), now)
	if got.SrcIP != "203.0.113.5" {
		t.Errorf("addresses are stored canonical: %q", got.SrcIP)
	}
}

func ev(mod func(*model.Event)) model.Event {
	e := model.Event{Kind: model.KindSudo, Severity: model.SevInfo, User: "root", Args: map[string]string{"cmd": "systemctl restart nginx --now"}}
	if mod != nil {
		mod(&e)
	}
	return e
}

func TestMatchIsExact(t *testing.T) {
	r, _ := Validate(rule(nil), now)
	if !r.Matches(ev(nil), now) {
		t.Fatal("the expected activity must match")
	}
	for name, e := range map[string]model.Event{
		"another kind":    ev(func(e *model.Event) { e.Kind = model.KindUserChange }),
		"another user":    ev(func(e *model.Event) { e.User = "bob" }),
		"another command": ev(func(e *model.Event) { e.Args = map[string]string{"cmd": "rm -rf /"} }),
		"no command":      ev(func(e *model.Event) { e.Args = nil }),
		"critical":        ev(func(e *model.Event) { e.Severity = model.SevCritical }),
	} {
		if r.Matches(e, now) {
			t.Errorf("%s matched", name)
		}
	}
	if r.Matches(ev(nil), now.Add(48*time.Hour)) {
		t.Error("an expired exception matched")
	}
}

func TestMatchFields(t *testing.T) {
	r, _ := Validate(Rule{Kind: model.KindSSHLoginFail, SrcIP: "203.0.113.0/24", Reason: "office scanner", ExpiresAt: now.Add(time.Hour)}, now)
	hit := model.Event{Kind: model.KindSSHLoginFail, Severity: model.SevWarn, SrcIP: "203.0.113.77"}
	miss := model.Event{Kind: model.KindSSHLoginFail, Severity: model.SevWarn, SrcIP: "198.51.100.1"}
	if !r.Matches(hit, now) || r.Matches(miss, now) || r.Matches(model.Event{Kind: model.KindSSHLoginFail, Severity: model.SevWarn}, now) {
		t.Error("network match")
	}
	c, _ := Validate(Rule{Kind: model.KindSudo, LoginUser: "alice", Exe: "/usr/bin/sudo", Reason: "r", ExpiresAt: now.Add(time.Hour)}, now)
	good := model.Event{Kind: model.KindSudo, Severity: model.SevInfo, Context: &model.Context{LoginUser: "alice", Exe: "/usr/bin/sudo"}}
	other := model.Event{Kind: model.KindSudo, Severity: model.SevInfo, Context: &model.Context{LoginUser: "bob", Exe: "/usr/bin/sudo"}}
	if !c.Matches(good, now) || c.Matches(other, now) || c.Matches(model.Event{Kind: model.KindSudo}, now) {
		t.Error("context match")
	}
}
