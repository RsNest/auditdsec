// Package sanitize is the one boundary between what auditd wrote and what the
// agent keeps, logs, serves or sends. An audit record can carry a secret in
// places a plain text search does not see: a hex-encoded PROCTITLE whose
// arguments are separated by NUL bytes, EXECVE arguments a0, a1, a2 ... where
// "-p" and its password are two different fields, a hex-encoded sudo command,
// terminal input. Everything that leaves the pipeline as stored evidence, a
// notification plan, a log line or an API answer goes through here first.
//
// The rules are:
//   - hex values are decoded (bounded) and the arguments are masked as an
//     argument vector (redact.Argv), split across fields or records included;
//   - a value that should have been hex but cannot be decoded is replaced by an
//     explicit marker, never copied through (hex is reversible);
//   - terminal input is dropped;
//   - the flat-text patterns of redact.String run over the result as a second
//     layer;
//   - the result is idempotent: sanitizing sanitized text changes nothing.
//
// It is pattern based, not a guarantee: a secret in an argument of an unknown
// program, or typed after a prompt, is not recognised.
package sanitize

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/redact"
)

// Markers that replace what could not or must not be kept.
const (
	Undecodable   = "[redacted: undecodable value]"
	TerminalInput = "[redacted: terminal input]"
)

// Bounds. Decoding and rendering never grow with the input.
const (
	maxDecoded = 8192 // bytes decoded from one hex value
	maxArgText = 1024 // bytes kept of one rendered argument
	maxArgs    = 128  // arguments rendered for one command
)

var (
	execArg  = regexp.MustCompile(`^a(\d{1,5})(?:\[(\d{1,5})\])?$`)
	recType  = regexp.MustCompile(`\btype=([A-Z_0-9]{1,40})\b`)
	hexLike  = regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	hexKeys  = map[string]bool{"comm": true, "exe": true, "name": true, "path": true, "ocomm": true, "cwd": true, "acct": true}
	cmdKeys  = map[string]bool{"cmd": true, "proctitle": true}
	termType = map[string]bool{"TTY": true, "USER_TTY": true}
)

// pair is one key=value of an audit line. ts..te is the value token with its
// quotes; vs..ve the content between them.
type pair struct {
	key        string
	ts, te     int
	vs, ve     int
	quote      byte
	line       int
	recordType string
}

type rep struct {
	start, end int
	text       string
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' }

// scan walks the key=value pairs of s (offsets are reported as base+i) and
// descends into the msg='...' of user-space records.
func scan(s string, base int, emit func(pair)) {
	i := 0
	for i < len(s) {
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i >= len(s) {
			return
		}
		ks := i
		for i < len(s) && s[i] != '=' && !isSpace(s[i]) {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			for i < len(s) && !isSpace(s[i]) {
				i++
			}
			continue
		}
		key := s[ks:i]
		i++
		if i < len(s) && (s[i] == '"' || s[i] == '\'') {
			q := s[i]
			end := strings.IndexByte(s[i+1:], q)
			if end < 0 { // unterminated: the value runs to the end
				emit(pair{key: key, ts: base + i, te: base + len(s), vs: base + i + 1, ve: base + len(s), quote: q})
				return
			}
			emit(pair{key: key, ts: base + i, te: base + i + 2 + end, vs: base + i + 1, ve: base + i + 1 + end, quote: q})
			if key == "msg" && q == '\'' {
				scan(s[i+1:i+1+end], base+i+1, emit)
			}
			i += 2 + end
			continue
		}
		vs := i
		for i < len(s) && !isSpace(s[i]) {
			i++
		}
		emit(pair{key: key, ts: base + vs, te: base + i, vs: base + vs, ve: base + i})
	}
}

// decoded is the content of a value after hex decoding.
type decoded struct {
	text      string // printable; NUL bytes are kept as \x00 for the caller to split
	bad       bool   // looked like hex but could not be decoded
	truncated bool
}

// decodeValue decodes an unquoted value that auditd hex-encoded. A quoted
// value is plain text. An unquoted value that is not made of hex digits is
// plain text too (auditd never writes one for these keys, but an old or odd
// producer might).
func decodeValue(v string, quoted bool) decoded {
	if quoted || v == "" || !hexLike.MatchString(v) {
		return decoded{text: v}
	}
	if len(v)%2 != 0 {
		return decoded{bad: true}
	}
	trunc := false
	if len(v) > 2*maxDecoded {
		v, trunc = v[:2*maxDecoded], true
	}
	b := make([]byte, len(v)/2)
	for i := range b {
		hi, lo := unhex(v[2*i]), unhex(v[2*i+1])
		b[i] = hi<<4 | lo
	}
	return decoded{text: string(b), truncated: trunc}
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// printable replaces what cannot be shown: control bytes and invalid UTF-8
// become '?'. NUL is kept for splitting by the caller.
func printable(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			b.WriteByte('?')
		case r == 0:
			b.WriteByte(0)
		case r < 0x20 && r != '\t', r == 0x7f:
			b.WriteByte('?')
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// clip bounds text to n bytes at a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// quote renders text as a double-quoted audit value. The audit format has no
// escapes, and a value can sit inside msg='...', so neither kind of quote may
// appear in it: an apostrophe (the quoting of a word with spaces) is shown as
// a backtick, which redact.SplitCommand reads back as the same quote, and a
// double quote as a typographic one.
func quote(s string) string {
	s = strings.NewReplacer("'", "`", `"`, "”").Replace(s)
	return `"` + s + `"`
}

// argsOf splits NUL-separated argv text.
func argsOf(text string) []string {
	return strings.Split(strings.TrimRight(text, "\x00"), "\x00")
}

// renderArgs masks an argument vector and renders it on one line.
func renderArgs(args []string, trunc bool) string {
	if len(args) > maxArgs {
		args = append(args[:maxArgs:maxArgs], "…")
	}
	for i := range args {
		args[i] = clip(printable(args[i]), maxArgText)
	}
	out := redact.Join(redact.Argv(args))
	if trunc {
		out += " …"
	}
	return out
}

// rewrite sanitizes audit lines, one record per line, with the context of the
// whole set: the EXECVE arguments of an event are masked as one vector even
// when auditd split them over several records.
func rewrite(lines []string) []string {
	out := make([]string, len(lines))
	reps := make([][]rep, len(lines))

	type argRef struct {
		idx, frag int
		p         pair
	}
	var refs []argRef
	for li, line := range lines {
		li := li
		rt := ""
		if m := recType.FindStringSubmatch(line); m != nil {
			rt = m[1]
		}
		scan(line, 0, func(p pair) {
			p.line, p.recordType = li, rt
			val := line[p.vs:p.ve]
			switch {
			case p.key == "msg":
				// the nested pairs are visited on their own
			case rt == "EXECVE" && execArg.MatchString(p.key):
				m := execArg.FindStringSubmatch(p.key)
				idx, _ := strconv.Atoi(m[1])
				frag := -1
				if m[2] != "" {
					frag, _ = strconv.Atoi(m[2])
				}
				refs = append(refs, argRef{idx: idx, frag: frag, p: p})
			case p.key == "data" && termType[rt]:
				reps[li] = append(reps[li], rep{p.ts, p.te, quote(TerminalInput)})
			case cmdKeys[p.key]:
				d := decodeValue(val, p.quote != 0)
				var text string
				switch {
				case d.bad:
					text = Undecodable
				case p.key == "proctitle" && p.quote == 0:
					text = renderArgs(argsOf(d.text), d.truncated)
				default:
					text = redact.Command(clip(printable(strings.ReplaceAll(d.text, "\x00", " ")), maxDecoded))
					if d.truncated {
						text += " …"
					}
				}
				reps[li] = append(reps[li], rep{p.ts, p.te, quote(text)})
			case hexKeys[p.key] && p.quote == 0:
				d := decodeValue(val, false)
				if d.bad || d.text == val {
					return // odd length or plain: left to the text patterns
				}
				if looksPrintableHex(d.text) {
					reps[li] = append(reps[li], rep{p.ts, p.te, quote(redact.String(clip(printable(d.text), maxArgText)))})
				}
			}
		})
	}

	if len(refs) > 0 {
		// Reassemble the arguments in order; fragments a1[0], a1[1] of one
		// argument are joined.
		sort.SliceStable(refs, func(i, j int) bool {
			if refs[i].idx != refs[j].idx {
				return refs[i].idx < refs[j].idx
			}
			return refs[i].frag < refs[j].frag
		})
		var args []string
		var first []int // index in refs of each argument's first token
		last := -1
		bad := map[int]bool{}
		for ri, r := range refs {
			if r.idx != last {
				args = append(args, "")
				first = append(first, ri)
				last = r.idx
			}
			val := lines[r.p.line][r.p.vs:r.p.ve]
			d := decodeValue(val, r.p.quote != 0)
			text := d.text
			if d.bad {
				text, bad[len(args)-1] = Undecodable, true
			}
			args[len(args)-1] += strings.ReplaceAll(text, "\x00", " ")
			if d.truncated {
				args[len(args)-1] += "…"
			}
		}
		for i := range args {
			args[i] = clip(printable(args[i]), maxArgText)
		}
		masked := redact.Argv(args)
		for ai := range masked {
			if bad[ai] {
				masked[ai] = Undecodable
			}
		}
		fi := 0
		for ri, r := range refs {
			// advance to this token's argument
			for fi+1 < len(first) && first[fi+1] <= ri {
				fi++
			}
			text := ""
			if ri == first[fi] {
				text = masked[fi]
				if fi >= maxArgs {
					text = "…"
				}
			}
			reps[r.p.line] = append(reps[r.p.line], rep{r.p.ts, r.p.te, quote(text)})
		}
	}

	for li, line := range lines {
		rs := reps[li]
		sort.Slice(rs, func(i, j int) bool { return rs[i].start < rs[j].start })
		var b strings.Builder
		prev := 0
		for _, r := range rs {
			if r.start < prev {
				continue
			}
			b.WriteString(line[prev:r.start])
			b.WriteString(r.text)
			prev = r.end
		}
		b.WriteString(line[prev:])
		out[li] = redact.String(b.String())
	}
	return out
}

// looksPrintableHex mirrors the parser's rule for hex-encoded names: mostly
// printable once decoded, so a plain word is not mistaken for hex.
func looksPrintableHex(s string) bool {
	if s == "" {
		return false
	}
	ok := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == 0 || c == '\t' || (c >= 0x20 && c < 0x7f) {
			ok++
		}
	}
	return ok*5 >= len(s)*4
}

// Lines sanitizes the raw lines of one audit event (one record per line).
func Lines(lines []string) []string { return rewrite(lines) }

// AuditRaw returns the sanitized evidence text of one event, bounded to max
// bytes. Records are joined by newlines.
func AuditRaw(lines []string, max int) string {
	return clip(strings.Join(rewrite(lines), "\n"), max)
}

// Raw sanitizes stored or logged evidence text: audit lines separated by
// newlines. It is what the API applies to events written by older versions.
func Raw(s string) string {
	if s == "" {
		return s
	}
	return strings.Join(rewrite(strings.Split(s, "\n")), "\n")
}

// Line sanitizes one audit line on its own, without the context of the other
// records of its event (use Lines when the event is available).
func Line(s string) string { return rewrite([]string{s})[0] }

// RecordType returns the type of an audit line, such as "EXECVE", without
// touching any value; it is what debug logging prints instead of the line.
func RecordType(line string) string {
	if m := recType.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

// Command sanitizes the cmd of a record from the record's own text, so that
// an undecodable value is replaced instead of passed through as hex.
func Command(lines []string) string {
	for _, l := range lines {
		var got string
		scan(l, 0, func(p pair) {
			if p.key != "cmd" || got != "" {
				return
			}
			d := decodeValue(l[p.vs:p.ve], p.quote != 0)
			if d.bad {
				got = Undecodable
				return
			}
			got = redact.Command(clip(printable(strings.ReplaceAll(d.text, "\x00", " ")), maxDecoded))
			if d.truncated {
				got += " …"
			}
		})
		if got != "" {
			return got
		}
	}
	return ""
}

// Text masks free text: an error message, a detail, a path.
func Text(s string) string { return redact.String(s) }

// Event is the final guard applied to every event before it is journaled,
// planned for delivery, handed to the detector or sent: whatever built it,
// no field carries a secret the patterns know. It is idempotent.
func Event(ev model.Event) model.Event {
	ev.Raw = Raw(ev.Raw)
	ev.User = redact.String(ev.User)
	ev.Incomplete = redact.String(ev.Incomplete)
	if c := ev.Context; c != nil {
		cc := *c
		cc.LoginUser = redact.String(cc.LoginUser)
		cc.EffectiveUser = redact.String(cc.EffectiveUser)
		cc.Exe = redact.String(cc.Exe)
		cc.Command = redact.Command(cc.Command)
		if cc.Session != nil {
			s := *cc.Session
			s.Note = redact.String(s.Note)
			cc.Session = &s
		}
		ev.Context = &cc
	}
	if ev.Args != nil {
		args := make(map[string]string, len(ev.Args))
		for k, v := range ev.Args {
			if k == "cmd" {
				args[k] = redact.Command(v)
			} else {
				args[k] = redact.String(v)
			}
		}
		ev.Args = args
	}
	return ev
}
