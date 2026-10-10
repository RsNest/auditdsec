// Package redact masks secrets that show up inside command lines and other
// free text before they are stored, logged or sent to a chat. auditd records
// whole command lines, so a `mysql -psecret` or `curl -H "Authorization:
// Bearer ..."` would otherwise end up in Telegram and on disk.
//
// This package holds the text and argument-vector primitives. It knows
// nothing about audit records: internal/sanitize applies it to them (and is
// the boundary the rest of the agent goes through). Masking is a best effort
// on patterns, not a guarantee that no secret survives.
package redact

import (
	"regexp"
	"strings"
)

// Mask is what replaces a secret.
const Mask = "***"

// secretWords are the names that mark a value as a secret. They are matched
// inside a longer name too (DB_PASSWORD, x-api-key, "client_secret").
const secretWords = `password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|auth[_-]?token|access[_-]?key|private[_-]?key|credential`

var (
	// key=value / key: value for secret-looking keys, with optional quotes.
	// The key may carry a prefix or suffix (MYSQL_PWD, db.password.file).
	kvRe = regexp.MustCompile(`(?i)(\b[a-z0-9_.-]*(?:` + secretWords + `)[a-z0-9_.-]*|\bpass)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;"'` + "`" + `]+)`)

	// {"password": "x"}: a JSON member with a secret-looking name.
	jsonRe = regexp.MustCompile(`(?i)("[a-z0-9_.-]*(?:` + secretWords + `)[a-z0-9_.-]*"\s*:\s*)("(?:[^"\\]|\\.)*"|[^\s,}\]]+)`)

	// --password foo / --token foo (space separated long options).
	longOptRe = regexp.MustCompile(`(?i)(--(?:password|passwd|pass|passphrase|token|secret|api-key|apikey|auth-token|access-key|secret-key|client-secret|http-password|ftp-password|proxy-password|bearer))(\s+)("[^"]*"|'[^']*'|[^\s"'` + "`" + `]+)`)

	// Authorization: Bearer xxx / Basic xxx, with or without a quote around it.
	authHeaderRe = regexp.MustCompile(`(?i)(authorization\s*:\s*(?:bearer|basic|token|digest)\s+)([^\s"']+)`)

	// Other headers that carry a credential in their value.
	credHeaderRe = regexp.MustCompile(`(?i)((?:proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token)\s*:\s*)([^"'\r\n]+)`)

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
	out = jsonRe.ReplaceAllString(out, `${1}"`+Mask+`"`)
	out = longOptRe.ReplaceAllString(out, "${1}${2}"+Mask)
	out = authHeaderRe.ReplaceAllString(out, "${1}"+Mask)
	out = credHeaderRe.ReplaceAllString(out, "${1}"+Mask)
	out = urlCredRe.ReplaceAllString(out, "${1}"+Mask+"${3}")
	if shortPwToolRe.MatchString(out) {
		out = shortPwRe.ReplaceAllString(out, "${1}${2}"+Mask)
	}
	return out
}

// Args masks every value of a map, returning a new map. Keys are left alone.
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
