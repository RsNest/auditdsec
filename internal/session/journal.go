package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entry is the part of a systemd journal record the agent uses. Fields that
// start with an underscore are added by journald itself and cannot be forged
// by the logging process; MESSAGE and SYSLOG_IDENTIFIER can.
type Entry struct {
	Time    time.Time
	PID     string // _PID
	Comm    string // _COMM
	UID     string // _UID
	BootID  string // _BOOT_ID
	Message string // MESSAGE
}

// Reader returns journal entries since a time, at most limit of them. It is the
// seam for tests and for hosts without journald.
type Reader interface {
	Read(ctx context.Context, since time.Time, limit int) ([]Entry, error)
}

// ParseJSON parses one line of `journalctl -o json`. MESSAGE may be a string or,
// when it is not valid UTF-8, an array of byte values; the latter is ignored,
// as are lines without a trustworthy origin.
func ParseJSON(line []byte) (Entry, bool) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(line, &raw) != nil {
		return Entry{}, false
	}
	str := func(k string) string {
		var s string
		if json.Unmarshal(raw[k], &s) != nil {
			return ""
		}
		return s
	}
	us, err := strconv.ParseInt(str("__REALTIME_TIMESTAMP"), 10, 64)
	if err != nil {
		return Entry{}, false
	}
	e := Entry{
		Time: time.UnixMicro(us).UTC(), PID: str("_PID"), Comm: str("_COMM"), UID: str("_UID"),
		BootID: str("_BOOT_ID"), Message: str("MESSAGE"),
	}
	if e.Message == "" || e.PID == "" {
		return Entry{}, false
	}
	return e, true
}

var acceptedRe = regexp.MustCompile(`^Accepted (\S+) for (\S{1,64}) from (\S+) port (\d{1,5})(?: ssh2)?(?::|$| )`)

// ParseAccepted extracts a login from an sshd "Accepted" line. The process
// must be sshd running as root, by journald's own fields: any local user can
// write "Accepted ..." into the journal under the identifier sshd with
// logger(1), but not with _COMM=sshd and _UID=0. The message is not stored.
func ParseAccepted(e Entry) (Accepted, bool) {
	if e.UID != "0" || (e.Comm != "sshd" && e.Comm != "sshd-session") {
		return Accepted{}, false
	}
	m := acceptedRe.FindStringSubmatch(e.Message)
	if m == nil {
		return Accepted{}, false
	}
	return Accepted{Time: e.Time, PID: e.PID, User: m[2], Addr: m[3], Port: m[4]}, true
}

// ExecReader reads the journal with journalctl, read-only, with a timeout and
// output caps. It filters by the trusted fields so the host does the work.
type ExecReader struct {
	Bin     string
	Timeout time.Duration
	MaxOut  int
	// Exec runs a command and returns its (capped) standard output.
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
}

type capBuf struct {
	buf bytes.Buffer
	max int
}

func (c *capBuf) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil // never fail the child: it would only die of SIGPIPE
}

func (r ExecReader) Read(ctx context.Context, since time.Time, limit int) ([]Entry, error) {
	bin, timeout, maxOut := r.Bin, r.Timeout, r.MaxOut
	if bin == "" {
		bin = "journalctl"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if maxOut <= 0 {
		maxOut = 4 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := []string{"--no-pager", "-o", "json", "--utc", "-n", strconv.Itoa(limit),
		"--since", "@" + strconv.FormatInt(since.Unix(), 10), "_UID=0", "_COMM=sshd", "_COMM=sshd-session"}
	run := r.Exec
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			out := &capBuf{max: maxOut}
			cmd.Stdout = out
			var errBuf capBuf
			errBuf.max = 512
			cmd.Stderr = &errBuf
			if err := cmd.Run(); err != nil {
				return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(errBuf.buf.String()))
			}
			return out.buf.Bytes(), nil
		}
	}
	data, err := run(ctx, bin, args...)
	if err != nil {
		return nil, err
	}
	var out []Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 64<<10)
	for sc.Scan() && len(out) < limit {
		if e, ok := ParseJSON(sc.Bytes()); ok {
			out = append(out, e)
		}
	}
	return out, nil // an over-long line ends the scan; the rest is simply not read
}

// Follower feeds the tracker from a Reader in the background. It never blocks
// ingestion: it runs in its own goroutine, one bounded read at a time, and a
// failure only disables it for a while.
type Follower struct {
	Tracker  *Tracker
	Reader   Reader
	Every    time.Duration
	Lookback time.Duration
	Limit    int
	BootID   func() string
	Log      *slog.Logger
	Now      func() time.Time

	mu     sync.Mutex
	state  string
	reason string
	last   time.Time
}

// States of a Follower.
const (
	JournalActive      = "active"
	JournalUnavailable = "unavailable"
	JournalStarting    = "starting"
)

func (f *Follower) defaults() {
	if f.Every <= 0 {
		f.Every = 30 * time.Second
	}
	if f.Lookback <= 0 {
		f.Lookback = 24 * time.Hour
	}
	if f.Limit <= 0 {
		f.Limit = 2000
	}
	if f.Now == nil {
		f.Now = time.Now
	}
	if f.BootID == nil {
		f.BootID = func() string { return "" }
	}
	if f.Log == nil {
		f.Log = slog.Default()
	}
}

// Status reports whether the journal is being read, and why not.
func (f *Follower) Status() (state, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == "" {
		return JournalStarting, ""
	}
	return f.state, f.reason
}

// PollOnce performs one bounded read and feeds the tracker. Lines from another
// boot are dropped: their PIDs mean nothing now.
func (f *Follower) PollOnce(ctx context.Context) error {
	f.defaults()
	f.mu.Lock()
	since := f.last
	f.mu.Unlock()
	now := f.Now()
	if since.IsZero() || now.Sub(since) > f.Lookback {
		since = now.Add(-f.Lookback)
	} else {
		since = since.Add(-5 * time.Second) // overlap; duplicates are ignored
	}
	entries, err := f.Reader.Read(ctx, since, f.Limit)
	if err != nil {
		return err
	}
	boot := f.BootID()
	var list []Accepted
	newest := since
	for _, e := range entries {
		if e.Time.After(newest) {
			newest = e.Time
		}
		if boot != "" && e.BootID != "" && e.BootID != boot {
			continue
		}
		if a, ok := ParseAccepted(e); ok {
			list = append(list, a)
		}
	}
	f.Tracker.AddAccepted(list)
	f.mu.Lock()
	f.last = newest
	f.mu.Unlock()
	return nil
}

// Run polls until ctx ends. After a failure it backs off up to five minutes.
func (f *Follower) Run(ctx context.Context) {
	f.defaults()
	wait := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		err := f.PollOnce(ctx)
		f.mu.Lock()
		switch {
		case err == nil:
			if f.state != JournalActive {
				f.Log.Info("reading sshd logins from the journal to place sessions without an address")
			}
			f.state, f.reason = JournalActive, ""
			wait = f.Every
		case errors.Is(err, context.Canceled):
			f.mu.Unlock()
			return
		default:
			if f.state != JournalUnavailable {
				f.Log.Info("the journal cannot be read; sessions without an address in the audit log stay unattributed",
					"error", oneLine(err.Error()))
			}
			f.state, f.reason = JournalUnavailable, oneLine(err.Error())
			wait = min(max(wait*2, f.Every), 5*time.Minute)
		}
		f.mu.Unlock()
	}
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
