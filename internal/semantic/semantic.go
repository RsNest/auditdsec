// Package semantic turns assembled auditd events into the human-readable
// events the rest of the agent works with. This is where auditd's vocabulary
// (USER_CMD, SYSCALL, auid=1000) becomes "this user ran this command".
package semantic

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/parse"
	"github.com/RsNest/auditdsec/internal/redact"
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
		Raw:  truncate(ev.Raw(), maxRaw),
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
		out.Kind = model.KindSSHLoginFail
		out.Severity = model.SevWarn
		out.User = userOf(ev)
		out.SrcIP = ipOf(ev)
		out.Args["ip"] = out.SrcIP

	case ev.Has("USER_CMD"):
		out.Kind = model.KindSudo
		out.Severity = model.SevInfo
		out.User = userOf(ev)
		cmd := redact.String(ev.Field("cmd"))
		out.Args["cmd"] = cmd
		out.Args["cwd"] = ev.Field("cwd")
		// The raw line carries the same command hex-encoded; replace it so the
		// stored evidence cannot be decoded back into a secret.
		if hexCmd := rawHexCmd(ev); hexCmd != "" {
			out.Raw = strings.ReplaceAll(out.Raw, hexCmd, cmd)
		}

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

	out.SummaryKey = "event." + string(out.Kind)
	out.Args["user"] = out.User
	out.Args["kind"] = string(out.Kind)
	out.Args = redact.Args(out.Args)
	return out, "", true
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

// HeartbeatLost builds the synthetic event reported when the audit log stops
// being written, which is the signal that matters most: silence from a
// compromised host looks exactly like silence from a quiet one.
func HeartbeatLost(host, detail string) model.Event {
	return model.Event{
		Host:       host,
		Kind:       model.KindAuditdStopped,
		Severity:   model.SevCritical,
		SummaryKey: "event." + string(model.KindAuditdStopped),
		Args:       map[string]string{"detail": detail, "kind": string(model.KindAuditdStopped)},
	}
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
	if p := ev.Paths(); len(p) > 0 {
		// The last PATH record is the file that was opened; earlier ones are
		// the parent directories auditd walked through.
		return p[len(p)-1]
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

// rawHexCmd returns the hex form of the sudo command as it appears in the log.
func rawHexCmd(ev *parse.Event) string {
	for _, r := range ev.Records {
		i := strings.Index(r.Raw, "cmd=")
		if i < 0 {
			continue
		}
		rest := r.Raw[i+4:]
		end := strings.IndexAny(rest, " '\"")
		if end < 0 {
			end = len(rest)
		}
		if cand := rest[:end]; isUpperHex(cand) {
			return cand
		}
	}
	return ""
}

func isUpperHex(s string) bool {
	if len(s) < 4 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
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
