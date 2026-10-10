package redact

import (
	"path"
	"regexp"
	"strings"
)

// Argv masks the secret-bearing arguments of one command, given as an argument
// vector. A flat-text pass (String) cannot see that "-p" and "hunter2" belong
// together when they are two arguments, or that a header or an environment
// assignment sits in a separate argument; the vector can. The result has the
// same length; only values are replaced. It is idempotent.
//
// What it recognises:
//   - secret-bearing long options, as "--password x" and "--password=x";
//   - per-tool options, e.g. sshpass -p x, redis-cli -a x, curl -u user:pass,
//     docker login -p x, openssl -passin pass:x;
//   - attached short forms, e.g. mysql -pSECRET, 7z -pSECRET;
//   - HTTP headers that carry credentials (-H "Authorization: Bearer x");
//   - NAME=value arguments whose NAME says secret (PGPASSWORD=x, API_KEY=x);
//   - sub-commands that take a secret ("mysqladmin password x",
//     "nmcli ... password x", "openssl passwd x", "chpasswd" fed by echo).
//
// It does not claim to recognise every possible secret: a password passed as
// a bare positional argument of an unknown tool is invisible to it.
func Argv(args []string) []string { return argvDepth(args, 0) }

// maxDepth bounds how deep a command inside an argument is looked into
// ("sh -c 'ssh h \"mysql -pX\"'").
const maxDepth = 3

func argvDepth(args []string, depth int) []string {
	out := append([]string(nil), args...)
	tools := toolsIn(out)
	masked := make([]bool, len(out))
	mask := func(i int) {
		if i >= 0 && i < len(out) {
			out[i] = Mask
			masked[i] = true
		}
	}
	chpasswd := false
	for _, a := range out {
		if base(a) == "chpasswd" {
			chpasswd = true
		}
	}

	for i := 0; i < len(out); i++ {
		if masked[i] {
			continue
		}
		a := out[i]

		// --option and --option=value
		if strings.HasPrefix(a, "--") && len(a) > 2 {
			name, val, has := strings.Cut(a, "=")
			lname := strings.ToLower(name)
			if has && toolFor(tools, userFlags, name) != "" {
				out[i] = name + "=" + maskUserPass(val)
				continue
			}
			switch {
			case secretLong[lname]:
				if has {
					out[i] = name + "=" + Mask
				} else {
					mask(i + 1)
					i++
				}
				continue
			case headerLong[lname]:
				if has {
					out[i] = name + "=" + maskHeader(val)
				} else if i+1 < len(out) {
					out[i+1] = maskHeader(out[i+1])
					i++
				}
				continue
			}
		}

		// Tool-specific options that take the secret as the next argument.
		if tool := toolFor(tools, sepFlags, a); tool != "" {
			if i+1 < len(out) {
				mask(i + 1)
				i++
			}
			continue
		}
		if toolFor(tools, userFlags, a) != "" && i+1 < len(out) {
			out[i+1] = maskUserPass(out[i+1])
			i++
			continue
		}
		if a == "-H" && i+1 < len(out) && (tools["curl"] || tools["wget"] || tools["http"] || tools["https"]) {
			out[i+1] = maskHeader(out[i+1])
			i++
			continue
		}
		if (a == "-b" || a == "--cookie") && tools["curl"] && i+1 < len(out) {
			mask(i + 1)
			i++
			continue
		}

		// Attached short options: mysql -pSECRET.
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
			if pre := attachedFor(tools, a); pre != "" {
				out[i] = pre + Mask
				continue
			}
		}

		// NAME=value where NAME says secret: PGPASSWORD=x, API_KEY=x.
		if name, _, ok := strings.Cut(a, "="); ok && envName.MatchString(name) && secretName.MatchString(name) {
			out[i] = name + "=" + Mask
			continue
		}

		// "password x": a sub-command or a keyword whose argument is the secret.
		if i > 0 && secretWord[strings.ToLower(a)] {
			j := i + 1
			for j < len(out) && strings.HasPrefix(out[j], "-") && len(out[j]) > 1 {
				j++ // options of the sub-command (openssl passwd -1 SECRET)
			}
			if j < len(out) {
				mask(j)
			}
			continue
		}

		// echo user:secret | chpasswd
		if chpasswd && colonPair.MatchString(a) && base(a) != "chpasswd" {
			out[i] = a[:strings.IndexByte(a, ':')+1] + Mask
			continue
		}
	}

	// htpasswd -b file user password: the password is the last argument.
	if tools["htpasswd"] {
		for i, a := range out {
			if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "b") && i < len(out)-1 {
				mask(len(out) - 1)
				break
			}
		}
	}
	if tools["mkpasswd"] {
		for i := len(out) - 1; i > 0; i-- {
			if !strings.HasPrefix(out[i], "-") {
				mask(i)
				break
			}
		}
	}

	for i := range out {
		if !masked[i] {
			out[i] = embedded(out[i], depth)
		}
	}
	return out
}

var (
	// Long options whose value is a secret.
	secretLong = set("--password", "--passwd", "--pass", "--passphrase", "--token", "--secret",
		"--api-key", "--apikey", "--auth-token", "--access-key", "--secret-key", "--client-secret",
		"--http-password", "--ftp-password", "--proxy-password", "--db-password", "--admin-password",
		"--root-password", "--bearer", "--bearer-token", "--registry-password", "--basic-auth-password")
	// Long options whose value is a header line.
	headerLong = set("--header")

	// Short or single-dash options that take the secret as the next argument,
	// by tool. "docker login" is special-cased in toolsIn.
	sepFlags = map[string]map[string]bool{
		"sshpass":      set("-p"),
		"useradd":      set("-p"),
		"usermod":      set("-p"),
		"zip":          set("-P"),
		"unzip":        set("-P"),
		"redis-cli":    set("-a"),
		"mongo":        set("-p"),
		"mongosh":      set("-p"),
		"mongodump":    set("-p"),
		"mongorestore": set("-p"),
		"ssh-keygen":   set("-N", "-P"),
		"ldapsearch":   set("-w"),
		"ldapmodify":   set("-w"),
		"ldapadd":      set("-w"),
		"ldapdelete":   set("-w"),
		"ldappasswd":   set("-w", "-a", "-s"),
		"openssl":      set("-pass", "-passin", "-passout", "-k"),
		"ipmitool":     set("-P"),
		"snmpwalk":     set("-A", "-X"),
		"snmpget":      set("-A", "-X"),
		"docker-login": set("-p"),
	}
	// Options whose next argument is user:password.
	userFlags = map[string]map[string]bool{
		"curl": set("-u", "--user", "--proxy-user", "-U"),
		"wget": set("--user"),
	}
	// Tools whose "-pSECRET" form attaches the secret to the option.
	attachedShort = map[string][]string{
		"mysql": {"-p"}, "mysqldump": {"-p"}, "mysqladmin": {"-p"}, "mariadb": {"-p"},
		"mariadb-dump": {"-p"}, "mysqlimport": {"-p"}, "mysqlcheck": {"-p"}, "mysqlpump": {"-p"},
		"7z": {"-p"}, "7za": {"-p"}, "7zr": {"-p"}, "rar": {"-p", "-hp"}, "unrar": {"-p", "-hp"},
		"sshpass": {"-p"},
	}
	secretWord = set("password", "passwd", "passphrase", "secret", "requirepass", "masterauth")

	envName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	secretName = regexp.MustCompile(`(?i)(passw|pwd|secret|token|credential|passphrase|api[_-]?key|access[_-]?key|private[_-]?key)`)
	colonPair  = regexp.MustCompile(`^[^\s:|]+:[^\s|]+$`)
	headerRe   = regexp.MustCompile(`(?i)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-[a-z-]*(?:token|secret|key))\s*:\s*)(.*)$`)
)

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

func base(a string) string { return strings.ToLower(path.Base(a)) }

// toolsIn finds the programs a command line starts: the first few arguments,
// by base name, so "sudo -u root mysql" and "env X=1 sshpass" are recognised.
// A registry login is marked as the pseudo-tool "docker-login".
func toolsIn(args []string) map[string]bool {
	tools := map[string]bool{}
	for i, a := range args {
		if i >= 6 {
			break
		}
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		tools[base(a)] = true
	}
	if tools["docker"] || tools["podman"] || tools["skopeo"] || tools["buildah"] || tools["helm"] {
		for _, a := range args {
			if a == "login" {
				tools["docker-login"] = true
			}
		}
	}
	return tools
}

// toolFor returns the tool in table whose option list contains a.
func toolFor(tools map[string]bool, table map[string]map[string]bool, a string) string {
	for t := range tools {
		if table[t][a] {
			return t
		}
	}
	return ""
}

// attachedFor returns the option prefix ("-p") when a is that option with the
// secret attached ("-pSECRET") for a tool in play.
func attachedFor(tools map[string]bool, a string) string {
	for t := range tools {
		for _, pre := range attachedShort[t] {
			if strings.HasPrefix(a, pre) && len(a) > len(pre) {
				return pre
			}
		}
	}
	return ""
}

// maskUserPass turns "user:secret" into "user:***".
func maskUserPass(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[:i+1] + Mask
	}
	return v
}

// maskHeader masks the value of a header that carries a credential.
func maskHeader(v string) string {
	if m := headerRe.FindStringSubmatch(v); m != nil {
		return m[1] + Mask
	}
	return v
}

// Word is one word of a command line: Text as it was written (quotes
// included) and Value as the program would see it.
type Word struct {
	Text  string
	Value string
}

// maxTokens bounds how many words of one command line are examined; whatever
// follows is kept as a single last word, which is still masked as text.
const maxTokens = 256

// SplitCommand splits a command line into words the way a shell would, with
// single and double quotes and backslash escapes. A line with an unbalanced
// quote is split on whitespace instead: sudo records a command without its
// quoting, so an apostrophe in an argument is not a quote.
func SplitCommand(s string) []Word {
	if toks, ok := shellSplit(s); ok {
		return toks
	}
	var out []Word
	for len(out) < maxTokens {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return out
		}
		end := strings.IndexAny(s, " \t")
		if end < 0 {
			end = len(s)
		}
		out = append(out, Word{Text: s[:end], Value: s[:end]})
		s = s[end:]
	}
	if rest := strings.TrimSpace(s); rest != "" {
		out = append(out, Word{Text: rest, Value: rest})
	}
	return out
}

func shellSplit(s string) ([]Word, bool) {
	var out []Word
	i := 0
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			return out, true
		}
		if len(out) >= maxTokens {
			rest := strings.TrimSpace(s[i:])
			return append(out, Word{Text: rest, Value: rest}), true
		}
		start := i
		var val strings.Builder
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			switch c := s[i]; c {
			case '\'', '`':
				// a backtick quotes like an apostrophe: sanitized evidence shows
				// quoted arguments that way, the audit line having no escapes
				end := strings.IndexByte(s[i+1:], c)
				if end < 0 {
					return nil, false
				}
				val.WriteString(s[i+1 : i+1+end])
				i += end + 2
			case '"':
				i++
				for {
					if i >= len(s) {
						return nil, false
					}
					if s[i] == '"' {
						i++
						break
					}
					if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\' || s[i+1] == '$') {
						i++
					}
					val.WriteByte(s[i])
					i++
				}
			case '\\':
				if i+1 < len(s) {
					val.WriteByte(s[i+1])
					i += 2
				} else {
					val.WriteByte(c)
					i++
				}
			default:
				val.WriteByte(c)
				i++
			}
		}
		out = append(out, Word{Text: s[start:i], Value: val.String()})
	}
}

// Command masks the secrets in one flat command line, such as the cmd of a
// sudo record. The line is split into words, the argument vector is masked
// (Argv), and only the words that changed are rewritten, so quoting and
// spacing of the rest are kept as far as a rebuilt line allows. The flat-text
// patterns of String run over the result as a second layer.
func Command(s string) string { return commandDepth(s, 0) }

func commandDepth(s string, depth int) string {
	if s == "" {
		return s
	}
	toks := SplitCommand(s)
	vals := make([]string, len(toks))
	for i, t := range toks {
		vals[i] = t.Value
	}
	masked := argvDepth(vals, depth)
	parts := make([]string, len(toks))
	for i, t := range toks {
		if masked[i] == t.Value {
			parts[i] = t.Text
		} else {
			parts[i] = Quote(masked[i])
		}
	}
	return String(strings.Join(parts, " "))
}

// Quote writes an argument the way a POSIX shell would read it back: unchanged
// when it is a plain word, single-quoted when it holds spaces, quotes or shell
// characters. SplitCommand reads this form, so Join and SplitCommand agree.
func Quote(a string) string {
	if a == "" {
		return `''`
	}
	if !strings.ContainsAny(a, " \t\"'\\|&;<>()$`") {
		return a
	}
	return `'` + strings.ReplaceAll(a, `'`, `'\''`) + `'`
}

// Join renders an argument vector as one line, quoting where needed.
func Join(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = Quote(a)
	}
	return strings.Join(parts, " ")
}

// embedded masks one argument. An argument with spaces may itself be a command
// line (sh -c "...", ssh host "...", a quoted pipeline), so it is looked
// into as one, a few levels deep; where that finds nothing new the argument
// is kept exactly as it was apart from the flat-text patterns.
func embedded(a string, depth int) string {
	flat := String(a)
	if depth >= maxDepth || !strings.ContainsAny(a, " \t") {
		return flat
	}
	deep := commandDepth(a, depth+1)
	if strings.Join(strings.Fields(deep), " ") == strings.Join(strings.Fields(flat), " ") {
		return flat
	}
	return deep
}
