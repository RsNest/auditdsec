// Package access describes changes to how the panel is reached (a domain, the
// server's IP, an SSH tunnel) in a form that can be checked, shown to a person
// and handed to the local control service.
//
// There is deliberately one implementation of applying such a change: the
// installer (./install.sh). This package never edits Compose files, proxy
// configuration or certificates. It validates structured parameters, builds the
// installer's argument list from a fixed template, and parses the progress the
// installer reports, so a value typed into the panel can never become anything
// but an argument of that one program.
package access

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/logging"
)

// Actions a change can ask for.
const (
	ActionCheck  = "check"
	ActionDomain = "domain"
	ActionIP     = "ip"
	ActionTunnel = "tunnel"
	ActionUpdate = "update"
)

// Params are the structured parameters of a change. Nothing else is accepted:
// no free-form argument, no path, no command.
type Params struct {
	Action    string `json:"action"`
	Site      string `json:"site,omitempty"`       // a domain (domain) or an address (ip, optional)
	Email     string `json:"email,omitempty"`      // Let's Encrypt contact
	HTTPSPort string `json:"https_port,omitempty"` // "auto" or 1..65535
	Lang      string `json:"lang,omitempty"`       // ru or en, for the installer's texts
	// TraceID joins this change to the request that asked for it (the panel's
	// request ID); the installer logs under it. Anything that is not an ID is
	// replaced by a fresh one.
	TraceID string `json:"trace_id,omitempty"`
}

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid parameters")

var (
	labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	emailRe = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$`)
)

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// NormalizeDomain lower-cases and checks a host name. It rejects what is not a
// plain ASCII host name: IP literals, ports, paths, whitespace, a leading dash
// (which would become an option), single labels and wildcards. A name with
// non-ASCII characters must be given in its punycode form.
func NormalizeDomain(in string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(in))
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 {
		return "", bad("a domain name is required (up to 253 characters)")
	}
	if _, err := netip.ParseAddr(strings.Trim(d, "[]")); err == nil {
		return "", bad("%q is an IP address; use the IP option for that", in)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", bad("%q is not a full domain name (for example panel.example.com)", in)
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", bad("%q has an invalid part %q (letters, digits and hyphens only; non-ASCII names in punycode)", in, l)
		}
	}
	return d, nil
}

// Validate checks and normalizes parameters. A rejected value is never passed
// on, even in part.
func Validate(p Params) (Params, error) {
	if !logging.ValidID(p.TraceID) {
		p.TraceID = logging.NewID()
	}
	switch p.Action {
	case ActionCheck, ActionUpdate, ActionTunnel:
		if p.Site != "" || p.Email != "" || p.HTTPSPort != "" {
			return Params{}, bad("%s takes no address, e-mail or port", p.Action)
		}
	case ActionDomain:
		d, err := NormalizeDomain(p.Site)
		if err != nil {
			return Params{}, err
		}
		p.Site = d
		if p.Email != "" && !emailRe.MatchString(p.Email) {
			return Params{}, bad("the e-mail address does not look valid")
		}
	case ActionIP:
		if p.Site != "" {
			a, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(p.Site), "[]"))
			if err != nil || a.Zone() != "" {
				return Params{}, bad("%q is not an IP address", p.Site)
			}
			p.Site = a.Unmap().String()
		}
		if p.Email != "" && !emailRe.MatchString(p.Email) {
			return Params{}, bad("the e-mail address does not look valid")
		}
	default:
		return Params{}, bad("unknown action %q", p.Action)
	}
	if p.HTTPSPort != "" && p.HTTPSPort != "auto" {
		n, err := strconv.Atoi(p.HTTPSPort)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p.HTTPSPort {
			return Params{}, bad("the HTTPS port must be auto or a number from 1 to 65535")
		}
	}
	if p.Lang != "" && p.Lang != "ru" && p.Lang != "en" {
		return Params{}, bad("language must be ru or en")
	}
	return p, nil
}

// Args builds the installer's argument list for validated parameters, from a
// fixed template. eventsFile is a path chosen by the control service.
func Args(p Params, eventsFile string) []string {
	args := []string{"--yes", "--lang", firstNonEmpty(p.Lang, "en"), "--action", p.Action}
	if p.Site != "" {
		args = append(args, "--site", p.Site)
	}
	if p.Email != "" {
		args = append(args, "--email", p.Email)
	}
	if p.HTTPSPort != "" {
		args = append(args, "--https-port", p.HTTPSPort)
	}
	if eventsFile != "" {
		args = append(args, "--events-file", eventsFile)
	}
	return args
}

// Command is the exact line a person runs on the server to make the same
// change. Every value was validated, and the characters allowed are the ones
// that need no quoting in a shell.
func Command(p Params) string {
	out := "./install.sh --action " + p.Action
	if p.Site != "" {
		out += " --site " + p.Site
	}
	if p.Email != "" {
		out += " --email " + p.Email
	}
	if p.HTTPSPort != "" {
		out += " --https-port " + p.HTTPSPort
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// PlanID identifies the exact change that was shown to the person, so that an
// apply request can be tied to it and a stale or altered one is refused.
func PlanID(p Params, currentURL string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{p.Action, p.Site, p.Email, p.HTTPSPort, currentURL}, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// States of a task.
const (
	StateQueued      = "queued"
	StateRunning     = "running"
	StateSucceeded   = "succeeded"
	StateFailed      = "failed"
	StateRolledBack  = "rolled_back"
	StateInterrupted = "interrupted"
)

// Event is one progress line reported by the installer.
type Event struct {
	At    time.Time `json:"at"`
	Kind  string    `json:"kind"` // stage, plan, failure, result
	State string    `json:"state"`
	Code  string    `json:"code,omitempty"`
	Text  string    `json:"text,omitempty"`
	Fix   string    `json:"fix,omitempty"`
}

// Task is a change in progress or finished. It survives page reloads and a
// restart of the control service; it contains no secret.
type Task struct {
	ID       string    `json:"id"`
	TraceID  string    `json:"trace_id,omitempty"` // find every log line of this change with it
	Params   Params    `json:"params"`
	State    string    `json:"state"`
	Stage    string    `json:"stage,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
	ExitCode int       `json:"exit_code"`
	Code     string    `json:"code,omitempty"`  // the installer's diagnosed failure code
	Cause    string    `json:"cause,omitempty"` // what went wrong
	Fix      string    `json:"fix,omitempty"`   // what to do about it
	Events   []Event   `json:"events,omitempty"`
	LogTail  string    `json:"log_tail,omitempty"`
}

// Active reports whether the task has not finished.
func (t Task) Active() bool { return t.State == StateQueued || t.State == StateRunning }

// Apply folds one event into the task.
func (t *Task) Apply(e Event) {
	t.Events = append(t.Events, e)
	if len(t.Events) > 200 {
		t.Events = t.Events[len(t.Events)-200:]
	}
	switch e.Kind {
	case "stage":
		t.Stage = e.Code
	case "failure":
		if t.Code == "" {
			t.Code, t.Cause, t.Fix = e.Code, e.Text, e.Fix
		}
	case "result":
		switch e.State {
		case "ok":
			t.State = StateSucceeded
		case "rolled_back":
			t.State = StateRolledBack
			if t.Code == "" {
				t.Code, t.Cause = e.Code, e.Text
			}
		default:
			t.State = StateFailed
			if t.Code == "" {
				t.Code, t.Cause = e.Code, e.Text
			}
		}
	}
}
