package logging

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Limits on a trace lookup. A lookup reads a bounded amount and returns a
// bounded number of records, so a large directory cannot make it a problem.
const (
	TraceMaxLines = 5000
	TraceMaxBytes = 256 << 20
)

var jsonStreamRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*\.jsonl(\.[0-9]+(\.gz)?)?$`)

type traceLine struct {
	ts   string
	file string
	n    int
	line string
}

// FindTrace returns every record of the operation with this trace ID from all
// JSON streams in dir, rotated and compressed archives included, oldest first.
// truncated says that a limit cut the answer short.
func FindTrace(dir, id string) (lines []string, truncated bool, err error) {
	if !ValidID(id) {
		return nil, false, fmt.Errorf("a trace ID is 16 to 32 lower-case hex characters")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false, err
	}
	needle := `"trace_id":"` + id + `"`
	var found []traceLine
	var read int64
	for _, e := range entries {
		if !jsonStreamRe.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var r io.Reader = f
		var gz *gzip.Reader
		if strings.HasSuffix(e.Name(), ".gz") {
			if gz, err = gzip.NewReader(f); err != nil {
				f.Close()
				continue
			}
			r = gz
		}
		sc := bufio.NewScanner(io.LimitReader(r, TraceMaxBytes-read))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		n := 0
		for sc.Scan() {
			n++
			line := sc.Text()
			read += int64(len(line)) + 1
			if !strings.Contains(line, needle) {
				continue
			}
			var head struct {
				TS string `json:"ts"`
			}
			if json.Unmarshal([]byte(line), &head) != nil {
				continue
			}
			found = append(found, traceLine{ts: head.TS, file: e.Name(), n: n, line: line})
		}
		f.Close()
		if read >= TraceMaxBytes {
			truncated = true
			break
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].ts != found[j].ts {
			return found[i].ts < found[j].ts
		}
		if found[i].file != found[j].file {
			return found[i].file < found[j].file
		}
		return found[i].n < found[j].n
	})
	if len(found) > TraceMaxLines {
		found, truncated = found[:TraceMaxLines], true
	}
	for _, f := range found {
		lines = append(lines, f.line)
	}
	return lines, truncated, nil
}
