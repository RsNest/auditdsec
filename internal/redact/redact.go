// Package redact masks secrets that show up inside command lines before they
// are stored or sent to a chat. auditd records whole command lines, so a
// `mysql -psecret` or `curl -H "Authorization: Bearer ..."` would otherwise end
// up in Telegram and on disk.
package redact

import (
	"encoding/hex"
	"regexp"
	"strings"
)

// Mask is what replaces a secret.
const Mask = "***"

var (
	// key=value / key: value for secret-looking keys, with optional quotes.
	kvRe = regexp.MustCompile(`(?i)\b(password|passwd|pass|pwd|token|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?key|private[_-]?key|credential|passphrase)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;"']+)`)

	// --password foo / --token foo (space separated long options).
	longOptRe = regexp.MustCompile(`(?i)(--(?:password|passwd|token|secret|api-key|apikey|auth-token|access-key|passphrase))(\s+)("[^"]*"|'[^']*'|[^\s]+)`)

	// Authorization: Bearer xxx / Basic xxx, with or without a quote around it.
	authHeaderRe = regexp.MustCompile(`(?i)(authorization\s*:\s*(?:bearer|basic|token)\s+)([^\s"']+)`)

	// scheme://user:password@host
	urlCredRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^:/?#\s@]+:)([^@/\s]+)(@)`)

	// Attached short password option, e.g. mysql -psecret. Only applied when
	// the command line mentions a client known to use that form, because `-p`
	// means something harmless in many other tools (cp -p, mkdir -p).
	shortPwRe     = regexp.MustCompile(`(^|\s)(-p)([^\s"']{3,})`)
	shortPwToolRe = regexp.MustCompile(`(?i)\b(mysql|mysqldump|mysqladmin|mariadb|mariadb-dump|psql|redis-cli|mongosh|mongo)\b`)
)

// String masks every secret it recognizes in s. It never grows the string
// beyond recognisable shape: keys, option names and URL users are preserved so
// the reader still understands what the command was doing.
func String(s string) string {
	if s == "" {
		return s
	}
	out := kvRe.ReplaceAllString(s, "${1}${2}"+Mask)
	out = longOptRe.ReplaceAllString(out, "${1}${2}"+Mask)
	out = authHeaderRe.ReplaceAllString(out, "${1}"+Mask)
	out = urlCredRe.ReplaceAllString(out, "${1}"+Mask+"${3}")
	if shortPwToolRe.MatchString(out) {
		out = shortPwRe.ReplaceAllString(out, "${1}${2}"+Mask)
	}
	return out
}

// Args masks every value of a map in place-safe fashion, returning a new map.
// Keys are left alone.
func Args(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = String(v)
	}
	return out
}

// hexValueRe matches the fields auditd hex-encodes when their value contains a
// space: those are exactly the fields that carry whole command lines.
var hexValueRe = regexp.MustCompile(`\b(cmd|proctitle)=([0-9A-F]{4,})\b`)

// AuditLine masks secrets in a raw auditd line, for debug logging. A command
// line that auditd stored as hex is decoded, masked and written back in
// readable form: hex is trivially reversible, so copying it into a log file
// would copy the password with it.
func AuditLine(s string) string {
	s = String(s)
	return hexValueRe.ReplaceAllStringFunc(s, func(m string) string {
		eq := strings.IndexByte(m, '=')
		key, val := m[:eq], m[eq+1:]
		b, err := hex.DecodeString(val)
		if err != nil {
			return m
		}
		plain := strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
		return key + `="` + String(plain) + `"`
	})
}

// Token masks an API token for log output, keeping only enough to tell two
// tokens apart. It is used so a misconfigured Telegram token can be debugged
// without ever writing the token itself to disk.
func Token(t string) string {
	if t == "" {
		return ""
	}
	if i := strings.IndexByte(t, ':'); i > 0 {
		// Telegram tokens look like 123456789:AA... — the numeric bot id is
		// not a secret, the part after the colon is.
		return t[:i] + ":" + Mask
	}
	if len(t) <= 4 {
		return Mask
	}
	return t[:2] + Mask
}
