// Package model holds the normalized event that flows through the whole
// pipeline: parse -> semantic -> detect -> notify/store.
package model

import (
	"fmt"
	"strings"
	"time"
)

// Severity is how much the owner of the machine should care.
type Severity int

const (
	// SevInfo is normal activity worth recording but not worth waking up for.
	SevInfo Severity = iota
	// SevWarn is suspicious activity that deserves a look.
	SevWarn
	// SevCritical is activity that typically accompanies a compromise.
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "info"
	case SevWarn:
		return "warn"
	case SevCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity accepts the names used in the config file.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SevInfo, nil
	case "warn", "warning":
		return SevWarn, nil
	case "critical", "crit":
		return SevCritical, nil
	default:
		return SevInfo, fmt.Errorf("unknown severity %q (want info, warn or critical)", s)
	}
}

// Kind is the semantic class of an event. The string values are stable: they
// appear in the stored JSONL, in i18n keys and in the `explain` subcommand.
type Kind string

const (
	KindSSHLoginOK           Kind = "ssh_login_ok"
	KindSSHLoginFail         Kind = "ssh_login_fail"
	KindAuthOK               Kind = "auth_ok"   // a login or authentication by another service (console, su, ...)
	KindAuthFail             Kind = "auth_fail" // a failed one
	KindLoginAfterBruteForce Kind = "login_after_bruteforce"
	KindSudo                 Kind = "sudo"
	KindUserChange           Kind = "user_change"
	KindAuthorizedKeysChange Kind = "authorized_keys_change"
	KindPersistence          Kind = "persistence"
	KindConfigChange         Kind = "config_change"
	KindLogTamper            Kind = "log_tamper"
	KindSuspiciousExec       Kind = "suspicious_exec"
	KindAuditdStopped        Kind = "auditd_stopped"
	KindPanelCert            Kind = "panel_cert"
)

// AllKinds lists every kind the agent can produce, in rough order of how
// often an operator will see it.
var AllKinds = []Kind{
	KindSSHLoginOK,
	KindSSHLoginFail,
	KindAuthOK,
	KindAuthFail,
	KindLoginAfterBruteForce,
	KindSudo,
	KindUserChange,
	KindAuthorizedKeysChange,
	KindPersistence,
	KindConfigChange,
	KindLogTamper,
	KindSuspiciousExec,
	KindAuditdStopped,
	KindPanelCert,
}

// ValidKind reports whether k is a kind this build knows about.
func ValidKind(k Kind) bool {
	for _, c := range AllKinds {
		if c == k {
			return true
		}
	}
	return false
}

// Event is one thing that happened, already translated out of auditd's
// vocabulary. SummaryKey plus Args render the human sentence through i18n, so
// the same event can be shown in any language.
type Event struct {
	// ID is stable across replay of the same source generation and record.
	ID         string            `json:"event_id,omitempty"`
	Time       time.Time         `json:"time"`
	Host       string            `json:"host"`
	Kind       Kind              `json:"kind"`
	Severity   Severity          `json:"severity"`
	User       string            `json:"user,omitempty"`
	SrcIP      string            `json:"src_ip,omitempty"`
	SummaryKey string            `json:"summary_key"`
	Args       map[string]string `json:"args,omitempty"`
	Raw        string            `json:"raw,omitempty"`
	// Incomplete says why the audit records behind this event were not all
	// seen (closed on a timeout, cut by a memory limit, records arriving
	// late). Empty for a complete event. The event is evidence either way,
	// but an incomplete one is not proof of everything that happened.
	Incomplete string `json:"incomplete,omitempty"`
}

// Arg returns one rendering argument, or the empty string.
func (e Event) Arg(name string) string {
	if e.Args == nil {
		return ""
	}
	return e.Args[name]
}

// DedupKey identifies "the same thing happening again", so repeated events can
// be grouped into one message instead of flooding the chat.
func (e Event) DedupKey() string {
	return strings.Join([]string{
		string(e.Kind),
		e.User,
		e.SrcIP,
		e.Arg("path"),
		e.Arg("cmd"),
		e.Arg("detail"),
	}, "|")
}
