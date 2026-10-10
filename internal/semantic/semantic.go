// Package semantic turns assembled auditd events into the human-readable
// events the rest of the agent works with. This is where auditd's vocabulary
// (USER_CMD, SYSCALL, auid=1000) becomes "this user ran this command".
package semantic

import (
	"fmt"
	"net"
	"path"
	"sort"
	"strings"

	"github.com/RsNest/auditdsec/internal/auditlog"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/parse"
	"github.com/RsNest/auditdsec/internal/sanitize"
)

// maxRaw caps the stored evidence per event.
const maxRaw = 4000

// Audit rule key names. The rules shipped in deploy/auditdsec.rules use exactly
// these names; changing one here means changing it there too.
const (
	KeyIdentity = "ads_identity" // /etc/passwd, /etc/shadow, /etc/group
	KeySudoers  = "ads_sudoers"  // /etc/sudoers and sudoers.d
	KeySSHKeys  = "ads_sshkeys"  // authorized_keys
	KeySSHD     = "ads_sshd"     // sshd_config
	KeyPersist  = "ads_persist"  // cron, systemd units, shell profiles
	KeyLogs     = "ads_logs"     // log files and audit configuration
	KeyModules  = "ads_modules"  // kernel module loading
	KeyExecTmp  = "ads_exec_tmp" // execution from /tmp, /dev/shm, /var/tmp
)

type rule struct {
	kind model.Kind
	sev  model.Severity
}

var keyRules = map[string]rule{
	KeyIdentity: {model.KindUserChange, model.SevCritical},
	KeySudoers:  {model.KindUserChange, model.SevCritical},
	KeySSHKeys:  {model.KindAuthorizedKeysChange, model.SevCritical},
	KeySSHD:     {model.KindConfigChange, model.SevWarn},
	KeyPersist:  {model.KindPersistence, model.SevWarn},
	KeyLogs:     {model.KindLogTamper, model.SevCritical},
	KeyModules:  {model.KindLogTamper, model.SevCritical},
	KeyExecTmp:  {model.KindSuspiciousExec, model.SevWarn},
}

// accountRecords are the auditd record types that mean "accounts, groups or
// privileges changed". The bool says whether it is critical on its own.
var accountRecords = map[string]model.Severity{
	"ADD_USER":       model.SevCritical,
	"DEL_USER":       model.SevCritical,
	"ADD_GROUP":      model.SevWarn,
	"DEL_GROUP":      model.SevWarn,
	"USER_MGMT":      model.SevCritical,
	"GRP_MGMT":       model.SevWarn,
	"CHGRP_ID":       model.SevWarn,
	"USER_CHAUTHTOK": model.SevWarn,
	"ROLE_ASSIGN":    model.SevCritical,
	"ROLE_REMOVE":    model.SevWarn,
	"ACCT_LOCK":      model.SevWarn,
	"ACCT_UNLOCK":    model.SevWarn,
}

// Mapper converts parsed events. It is stateless and safe to reuse.
type Mapper struct {
	host string
}

// New returns a Mapper that stamps events with the given host name.
func New(host string) *Mapper { return &Mapper{host: host} }

// Map returns the human event for an audit event. The second result is false
// for the many records that are pure noise (session bookkeeping, credential
// juggling), which the agent deliberately never reports.
func (m *Mapper) Map(ev *parse.Event) (model.Event, bool) {
	out, _, ok := m.MapVerbose(ev)
	return out, ok
}

// MapVerbose is Map plus the reason an event was dropped, which is what debug
// mode reports. "My alert never arrived" is the question this answers, so the
// reason is written for a person reading a log, not for a parser.
func (m *Mapper) MapVerbose(ev *parse.Event) (model.Event, string, bool) {
	out := model.Event{
		Time: ev.Time,
		Host: m.host,
		Args: map[string]string{},
	}

	switch {
	case ev.HasAny("DAEMON_END", "DAEMON_ABORT"):
		out.Kind = model.KindAuditdStopped
		out.Severity = model.SevCritical
		out.User = userOf(ev)
		out.Args["detail"] = firstNonEmpty(ev.Field("op"), "terminate")

	case ev.Has("CONFIG_CHANGE"):
		out.Kind = model.KindLogTamper
		out.Severity = model.SevCritical
		out.User = userOf(ev)
		out.Args["detail"] = configChangeDetail(ev)

	case ev.Has("USER_LOGIN"):
		ok := succeeded(ev)
		if !viaSSH(ev) {
			// A console or other local login is not an SSH login and has no
			// remote address to attribute; it must not be labelled as one.
			return localAuth(out, ev, ok, isRoot(ev)), "", true
		}
		out.Kind = model.KindSSHLoginFail
		out.Severity = model.SevWarn
		if ok {
			out.Kind = model.KindSSHLoginOK
			out.Severity = model.SevInfo
			if isRoot(ev) {
				out.Severity = model.SevCritical
			}
		}
		out.User = userOf(ev)
		out.SrcIP = ipOf(ev)
		out.Args["ip"] = out.SrcIP

	case ev.Has("USER_AUTH"):
		// A successful USER_AUTH is already covered by USER_LOGIN; reporting
		// both would double-count every login.
		if succeeded(ev) {
			return model.Event{}, "successful USER_AUTH is reported through USER_LOGIN instead", false
		}
		if !viaSSH(ev) {
			// sudo, su, cron and display managers also authenticate through
			// PAM. Their failures are not SSH attacks and must not feed the
			// SSH ban detector.
			return localAuth(out, ev, false, false), "", true
		}
		out.Kind = model.KindSSHLoginFail
		out.Severity = model.SevWarn
		out.User = userOf(ev)
		out.SrcIP = ipOf(ev)
		out.Args["ip"] = out.SrcIP

	case ev.Has("USER_CMD"):
		out.Kind = model.KindSudo
		out.Severity = model.SevInfo
		out.User = userOf(ev)
		// From the record itself: a value that cannot be decoded is replaced,
		// never passed through as reversible hex.
		out.Args["cmd"] = sanitize.Command(rawLines(ev))
		out.Args["cwd"] = ev.Field("cwd")

	case accountRecordOf(ev) != "":
		typ := accountRecordOf(ev)
		out.Kind = model.KindUserChange
		out.Severity = accountRecords[typ]
		out.User = userOf(ev)
		out.Args["detail"] = accountDetail(ev, typ)

	case len(ev.AuditKeys()) > 0:
		r, key, ok := matchKey(ev.AuditKeys())
		if !ok {
			return model.Event{}, fmt.Sprintf("no rule for audit key %q (keys the agent knows: %s)",
				strings.Join(ev.AuditKeys(), ","), strings.Join(knownKeys(), ", ")), false
		}
		// A watched file is only interesting when it was actually touched:
		// a failed open is noise from an unprivileged process.
		if ev.Has("SYSCALL") && ev.FieldOf("SYSCALL", "success") == "no" {
			return model.Event{}, fmt.Sprintf("the watched file was not touched: syscall failed (exit=%s)",
				ev.FieldOf("SYSCALL", "exit")), false
		}
		out.Kind = r.kind
		out.Severity = r.sev
		out.User = userOf(ev)
		out.Args["path"] = pathOf(ev)
		out.Args["detail"] = firstNonEmpty(pathOf(ev), key)
		out.Args["exe"] = ev.Field("exe")
		out.Args["key"] = key

	default:
		return model.Event{}, fmt.Sprintf("no rule for record types [%s] and no audit key",
			strings.Join(ev.Types(), ",")), false
	}

	if !ev.Complete {
		out.Incomplete = ev.IncompleteReason
	}
	out.Context = contextOf(ev, out)
	out.SummaryKey = "event." + string(out.Kind)
	out.Args["user"] = out.User
	out.Args["kind"] = string(out.Kind)
	// The evidence is rebuilt from the records with their arguments masked as
	// vectors, then the whole event passes the final guard.
	out.Raw = sanitize.AuditRaw(rawLines(ev), maxRaw)
	return sanitize.Event(out), "", true
}

// knownKeys lists the audit rule keys the agent acts on, for the debug message
// that fires when a rule file and this build disagree.
func knownKeys() []string {
	out := make([]string, 0, len(keyRules))
	for k := range keyRules {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AuditHealth builds the synthetic event reported when the agent cannot rely on
// the audit log. The two states are kept apart: an unreadable log (the agent is
// blind) is critical, a log that merely has not been written for a while is a
// warning, because a quiet host looks the same as a stopped auditd and the
// silence alone does not prove either.
func AuditHealth(host string, state auditlog.State, detail string) model.Event {
	ev := model.Event{
		Host:       host,
		Kind:       model.KindAuditdStopped,
		Severity:   model.SevCritical,
		SummaryKey: "event." + string(model.KindAuditdStopped),
		Args:       map[string]string{"detail": detail, "kind": string(model.KindAuditdStopped), "state": string(state)},
	}
	if state == auditlog.Silent {
		ev.Severity = model.SevWarn
		ev.SummaryKey = "event.audit_silent"
	}
	return ev
}

func accountRecordOf(ev *parse.Event) string {
	for _, r := range ev.Records {
		if _, ok := accountRecords[r.Type]; ok {
			return r.Type
		}
	}
	return ""
}

// matchKey picks the most severe rule among the keys attached to the event.
func matchKey(keys []string) (rule, string, bool) {
	var (
		best  rule
		name  string
		found bool
	)
	for _, k := range keys {
		r, ok := keyRules[k]
		if !ok {
			continue
		}
		if !found || r.sev > best.sev {
			best, name, found = r, k, true
		}
	}
	return best, name, found
}

func accountDetail(ev *parse.Event, typ string) string {
	parts := []string{strings.ToLower(strings.ReplaceAll(typ, "_", "-"))}
	if op := ev.Field("op"); op != "" && op != "?" {
		parts = []string{op}
	}
	if acct := ev.Field("acct"); acct != "" && acct != "?" {
		parts = append(parts, acct)
	} else if id := ev.Field("id"); id != "" && id != "?" {
		parts = append(parts, "id="+id)
	}
	if grp := ev.Field("grp"); grp != "" && grp != "?" {
		parts = append(parts, "group="+grp)
	}
	if exe := ev.Field("exe"); exe != "" && exe != "?" {
		parts = append(parts, "("+exe+")")
	}
	return strings.Join(parts, " ")
}

func configChangeDetail(ev *parse.Event) string {
	if v := ev.Field("audit_enabled"); v != "" {
		return "audit_enabled=" + v
	}
	if v := ev.Field("audit_backlog_limit"); v != "" {
		return "audit_backlog_limit=" + v
	}
	parts := []string{}
	if op := ev.Field("op"); op != "" {
		parts = append(parts, op)
	}
	if k := strings.Join(ev.AuditKeys(), ","); k != "" {
		parts = append(parts, k)
	}
	if len(parts) == 0 {
		return "config_change"
	}
	return strings.Join(parts, " ")
}

// userOf resolves who did it. acct is the name auditd itself recorded; auid is
// the login uid, which survives sudo and is therefore the useful one.
func userOf(ev *parse.Event) string {
	if a := ev.Field("acct"); valid(a) {
		return a
	}
	if a := ev.Field("auid"); valid(a) && a != "4294967295" && a != "unset" && a != "-1" {
		return "uid=" + a
	}
	if u := ev.Field("uid"); valid(u) {
		return "uid=" + u
	}
	return ""
}

func isRoot(ev *parse.Event) bool {
	if a := ev.Field("acct"); a == "root" {
		return true
	}
	if ev.Field("acct") != "" {
		return false
	}
	return ev.Field("auid") == "0" || (ev.Field("auid") == "" && ev.Field("uid") == "0")
}

// ipOf returns the source address when it is a real IP. A host name or auditd's
// "?" placeholder is not useful for banning, so it is dropped.
func ipOf(ev *parse.Event) string {
	for _, k := range []string{"addr", "hostname"} {
		v := ev.Field(k)
		if !valid(v) {
			continue
		}
		if ip := net.ParseIP(v); ip != nil && !ip.IsUnspecified() {
			return v
		}
	}
	return ""
}

func pathOf(ev *parse.Event) string {
	if p := ev.TargetPath(); p != "" {
		return p
	}
	return ev.Field("name")
}

func succeeded(ev *parse.Event) bool {
	switch ev.Field("res") {
	case "success", "1", "yes":
		return true
	case "failed", "0", "no":
		return false
	}
	return ev.Field("success") == "yes"
}

// rawLines is the original text of each record of the event.
func rawLines(ev *parse.Event) []string {
	lines := make([]string, len(ev.Records))
	for i, r := range ev.Records {
		lines[i] = r.Raw
	}
	return lines
}

func valid(s string) bool {
	return s != "" && s != "?" && s != "(null)" && s != "unset"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// PanelCertProblem builds the event reported when the certificate the panel
// actually serves is about to expire or no longer verifies. A renewal that
// failed quietly would otherwise only show when browsers start refusing.
func PanelCertProblem(host, detail string) model.Event {
	return model.Event{
		Host:       host,
		Kind:       model.KindPanelCert,
		Severity:   model.SevWarn,
		SummaryKey: "event." + string(model.KindPanelCert),
		Args:       map[string]string{"detail": detail, "kind": string(model.KindPanelCert)},
	}
}

// viaSSH reports whether an authentication record comes from sshd. The program
// that wrote the record decides, not the presence of an address: a failed sudo
// has none, and other network services (ftp, imap) have one.
func viaSSH(ev *parse.Event) bool {
	exe := ev.Field("exe")
	if valid(exe) {
		return strings.HasPrefix(path.Base(exe), "sshd")
	}
	// Records without exe: sshd sets terminal=ssh. Without either, a remote
	// address is the only evidence left, and the old behaviour is kept.
	if t := ev.Field("terminal"); valid(t) {
		return t == "ssh"
	}
	return ipOf(ev) != ""
}

// serviceOf names the program behind a non-SSH authentication.
func serviceOf(ev *parse.Event) string {
	if exe := ev.Field("exe"); valid(exe) {
		return path.Base(exe)
	}
	if t := ev.Field("terminal"); valid(t) {
		return t
	}
	return "local"
}

// localAuth fills in an authentication that did not come from sshd. It carries
// no SrcIP on purpose: the SSH detector and the suspect list key on it.
func localAuth(out model.Event, ev *parse.Event, ok, root bool) model.Event {
	out.Kind, out.Severity = model.KindAuthFail, model.SevWarn
	if ok {
		out.Kind, out.Severity = model.KindAuthOK, model.SevInfo
		if root {
			out.Severity = model.SevCritical
		}
	}
	out.User = userOf(ev)
	out.Args["service"] = serviceOf(ev)
	out.Args["user"] = out.User
	out.Args["kind"] = string(out.Kind)
	out.SummaryKey = "event." + string(out.Kind)
	if !ev.Complete {
		out.Incomplete = ev.IncompleteReason
	}
	out.Raw = sanitize.AuditRaw(rawLines(ev), maxRaw)
	return sanitize.Event(out)
}

// RequiredKeys lists the audit rule keys the agent acts on. A rule set that
// lacks one produces no events of that class, silently.
func RequiredKeys() []string { return knownKeys() }

// contextKinds are the kinds that describe an action by a process, for which
// "who really did this" matters. Authentication events carry their own address
// and are left alone.
var contextKinds = map[model.Kind]bool{
	model.KindSudo: true, model.KindUserChange: true, model.KindAuthorizedKeysChange: true,
	model.KindPersistence: true, model.KindConfigChange: true, model.KindLogTamper: true,
	model.KindSuspiciousExec: true,
}

func idOf(s string) string {
	if s == "" || s == "4294967295" || s == "-1" || len(s) > 10 {
		return ""
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return s
}

// contextOf collects what the records themselves say about the acting process:
// the login UID (which survives sudo), the identity the action ran as, the
// kernel session ID, the PIDs and the executable. Only explicit fields are used;
// the remote address of the session is added later by the session tracker,
// separately and with its own confidence.
func contextOf(ev *parse.Event, out model.Event) *model.Context {
	if !contextKinds[out.Kind] {
		return nil
	}
	c := &model.Context{
		LoginUID:  idOf(ev.Field("auid")),
		SessionID: idOf(ev.Field("ses")),
		PID:       idOf(ev.Field("pid")),
		PPID:      idOf(ev.FieldOf("SYSCALL", "ppid")),
	}
	switch {
	case ev.Has("USER_CMD"):
		// uid is the invoking user; the identity sudo runs as is acct.
		if a := ev.Field("acct"); valid(a) {
			c.EffectiveUser = sanitize.Text(a)
			if a == "root" {
				c.EffectiveUID = "0"
			}
		}
		c.Command = out.Args["cmd"]
	case idOf(ev.FieldOf("SYSCALL", "euid")) != "":
		c.EffectiveUID = idOf(ev.FieldOf("SYSCALL", "euid"))
	default:
		c.EffectiveUID = idOf(ev.Field("uid"))
	}
	if exe := ev.Field("exe"); valid(exe) {
		c.Exe = sanitize.Text(strings.Trim(exe, `"`))
	}
	if *c == (model.Context{}) {
		return nil
	}
	return c
}
