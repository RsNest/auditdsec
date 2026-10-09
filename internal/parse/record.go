// Package parse turns raw auditd log lines into records and groups the records
// that belong to one audit event. It deliberately knows nothing about the
// meaning of the fields: that is the semantic package's job.
package parse

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrSkip is returned for lines that carry no record (blank lines, separators).
var ErrSkip = errors.New("parse: no record on this line")

// Record is a single `type=... msg=audit(ts:serial): k=v ...` line. Fields holds
// the flat key/value pairs, including the ones nested inside the `msg='...'`
// part of USER_* records, with quotes removed and hex-encoded values decoded.
type Record struct {
	Type   string
	Time   time.Time
	Serial int64
	Fields map[string]string
	Raw    string
}

// Field returns a field value, or "".
func (r Record) Field(key string) string { return r.Fields[key] }

// AuditKeys returns the names set by `-k` in the audit rules. auditd separates
// several keys with a 0x01 byte when more than one rule matched.
func (r Record) AuditKeys() []string {
	v := r.Fields["key"]
	if v == "" || v == "(null)" {
		return nil
	}
	parts := strings.FieldsFunc(v, func(c rune) bool { return c == 0x01 })
	var out []string
	for _, p := range parts {
		for _, q := range strings.Split(p, `\x01`) {
			if q = strings.TrimSpace(q); q != "" && q != "(null)" {
				out = append(out, q)
			}
		}
	}
	return out
}

// ParseLine parses one line of audit.log.
func ParseLine(line string) (Record, error) {
	raw := strings.TrimRight(line, "\r\n")
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return Record{}, ErrSkip
	}

	const marker = "msg=audit("
	i := strings.Index(s, marker)
	if i < 0 {
		return Record{}, fmt.Errorf("%w: no audit timestamp: %s", ErrSkip, truncate(s, 80))
	}
	head := s[:i]
	rest := s[i+len(marker):]
	j := strings.IndexByte(rest, ')')
	if j < 0 {
		return Record{}, fmt.Errorf("parse: unterminated audit timestamp: %s", truncate(s, 80))
	}
	ts, serial, err := parseStamp(rest[:j])
	if err != nil {
		return Record{}, err
	}
	body := strings.TrimPrefix(strings.TrimSpace(rest[j+1:]), ":")

	fields := make(map[string]string, 16)
	for _, kv := range splitFields(head) {
		fields[kv.key] = unquote(kv.val)
	}
	for _, kv := range splitFields(body) {
		if kv.key == "msg" && kv.quote == '\'' {
			// USER_* records wrap their interesting fields in msg='...'.
			fields["msg"] = kv.val
			for _, in := range splitFields(kv.val) {
				if _, exists := fields[in.key]; !exists {
					fields[in.key] = decodeValue(in.key, in)
				}
			}
			continue
		}
		fields[kv.key] = decodeValue(kv.key, kv)
	}

	typ := fields["type"]
	if typ == "" {
		return Record{}, fmt.Errorf("%w: no type field: %s", ErrSkip, truncate(s, 80))
	}
	return Record{Type: typ, Time: ts, Serial: serial, Fields: fields, Raw: raw}, nil
}

// parseStamp reads "1760000000.123:456".
func parseStamp(s string) (time.Time, int64, error) {
	colon := strings.LastIndexByte(s, ':')
	if colon < 0 {
		return time.Time{}, 0, fmt.Errorf("parse: bad audit stamp %q", s)
	}
	serial, err := strconv.ParseInt(s[colon+1:], 10, 64)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("parse: bad audit serial in %q: %w", s, err)
	}
	secPart := s[:colon]
	msec := int64(0)
	if dot := strings.IndexByte(secPart, '.'); dot >= 0 {
		ms, err := strconv.ParseInt(secPart[dot+1:], 10, 64)
		if err != nil {
			return time.Time{}, 0, fmt.Errorf("parse: bad audit millis in %q: %w", s, err)
		}
		msec = ms
		secPart = secPart[:dot]
	}
	sec, err := strconv.ParseInt(secPart, 10, 64)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("parse: bad audit seconds in %q: %w", s, err)
	}
	return time.Unix(sec, msec*int64(time.Millisecond)).UTC(), serial, nil
}

type field struct {
	key   string
	val   string
	quote byte // 0, '"' or '\''
}

// splitFields tokenizes `k=v k="v with spaces" k='v'` into ordered pairs.
func splitFields(s string) []field {
	var out []field
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			break
		}
		eq := -1
		for j := i; j < len(s); j++ {
			if s[j] == '=' {
				eq = j
				break
			}
			if s[j] == ' ' || s[j] == '\t' {
				break
			}
		}
		if eq < 0 {
			// A bare token without '=' (for example a trailing word); skip it.
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			continue
		}
		key := s[i:eq]
		i = eq + 1
		if i < len(s) && (s[i] == '"' || s[i] == '\'') {
			q := s[i]
			end := strings.IndexByte(s[i+1:], q)
			if end < 0 {
				out = append(out, field{key: key, val: s[i+1:], quote: q})
				break
			}
			out = append(out, field{key: key, val: s[i+1 : i+1+end], quote: q})
			i = i + 2 + end
			continue
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		out = append(out, field{key: key, val: s[start:i]})
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// hexKeys are the fields auditd hex-encodes when their value contains spaces or
// other characters that would break the flat key=value format.
var hexKeys = map[string]bool{
	"cmd": true, "proctitle": true, "comm": true, "exe": true, "name": true,
	"path": true, "ocomm": true, "cwd": true, "acct": true, "data": true,
}

func decodeValue(key string, f field) string {
	if f.quote != 0 {
		return f.val
	}
	if !hexKeys[key] || !looksHexEncoded(f.val) {
		return f.val
	}
	b, err := hex.DecodeString(f.val)
	if err != nil {
		return f.val
	}
	// proctitle separates argv entries with NUL bytes.
	s := strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	if s == "" {
		return f.val
	}
	return s
}

// looksHexEncoded is deliberately strict: auditd emits uppercase hex, and a
// short word such as "dead" or "cafe" would otherwise be mistaken for one.
func looksHexEncoded(s string) bool {
	if len(s) < 4 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == 0x00 || c == '\t' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return printable*5 >= len(b)*4 // at least 80% printable
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
