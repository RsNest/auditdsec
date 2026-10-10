package auditlog

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RulesReport says which of the audit keys the agent acts on are present in a
// set of rule files. It reads files; it does not know what the kernel has
// loaded, which `auditctl -l` shows.
type RulesReport struct {
	Files   []string // files read
	Present []string // required keys found
	Missing []string // required keys not found: events under them are never produced
	Extra   []string // keys in the rules the agent has no use for
}

// OK reports whether every required key is present.
func (r RulesReport) OK() bool { return len(r.Missing) == 0 }

// KeysIn extracts the audit keys named by `-k key` or `-F key=key` in rule
// text. Comments and blank lines are ignored.
func KeysIn(text string) []string {
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		for i, w := range f {
			switch {
			case w == "-k" && i+1 < len(f):
				seen[f[i+1]] = true
			case strings.HasPrefix(w, "key="):
				seen[strings.TrimPrefix(w, "key=")] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CheckRules reads the given rule files (a directory contributes its *.rules
// files) and compares the keys found with the required ones.
func CheckRules(paths []string, required []string) (RulesReport, error) {
	var rep RulesReport
	have := map[string]bool{}
	for _, p := range paths {
		files := []string{p}
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			m, _ := filepath.Glob(filepath.Join(p, "*.rules"))
			sort.Strings(m)
			files = m
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return rep, fmt.Errorf("read %s: %w", f, err)
			}
			rep.Files = append(rep.Files, f)
			for _, k := range KeysIn(string(b)) {
				have[k] = true
			}
		}
	}
	req := map[string]bool{}
	for _, k := range required {
		req[k] = true
		if have[k] {
			rep.Present = append(rep.Present, k)
		} else {
			rep.Missing = append(rep.Missing, k)
		}
	}
	for k := range have {
		if !req[k] {
			rep.Extra = append(rep.Extra, k)
		}
	}
	sort.Strings(rep.Present)
	sort.Strings(rep.Missing)
	sort.Strings(rep.Extra)
	return rep, nil
}
