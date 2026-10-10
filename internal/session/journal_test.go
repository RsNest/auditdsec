package session_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/session"
)

// Lines shaped like `journalctl -o json` output of sshd on systemd hosts.
const (
	jsonAccepted = `{"__REALTIME_TIMESTAMP":"1760000001000000","_PID":"2001","_COMM":"sshd","_UID":"0","_BOOT_ID":"boot-1","SYSLOG_IDENTIFIER":"sshd","_SYSTEMD_UNIT":"ssh.service","MESSAGE":"Accepted publickey for alice from 203.0.113.9 port 51234 ssh2: ED25519 SHA256:abcdef"}`
	// OpenSSH 9.8 splits the daemon: the session process is sshd-session.
	jsonAcceptedSplit = `{"__REALTIME_TIMESTAMP":"1760000001000000","_PID":"2001","_COMM":"sshd-session","_UID":"0","_BOOT_ID":"boot-1","MESSAGE":"Accepted password for alice from 2001:db8::7 port 40022 ssh2"}`
	// The same text written by an unprivileged user with logger -t sshd.
	jsonForged = `{"__REALTIME_TIMESTAMP":"1760000001000000","_PID":"4242","_COMM":"logger","_UID":"1000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for alice from 198.51.100.66 port 1 ssh2"}`
	// A non-UTF-8 message arrives as an array of byte values.
	jsonBinary = `{"__REALTIME_TIMESTAMP":"1760000001000000","_PID":"2001","_COMM":"sshd","_UID":"0","MESSAGE":[65,99,99,255]}`
	jsonFailed = `{"__REALTIME_TIMESTAMP":"1760000001000000","_PID":"2001","_COMM":"sshd","_UID":"0","MESSAGE":"Failed password for invalid user Accepted from 203.0.113.9 port 22 ssh2"}`
)

func TestParseAcceptedFixtures(t *testing.T) {
	cases := []struct {
		name, line string
		want       session.Accepted
		ok         bool
	}{
		{"publickey", jsonAccepted, session.Accepted{PID: "2001", User: "alice", Addr: "203.0.113.9", Port: "51234"}, true},
		{"sshd-session and IPv6", jsonAcceptedSplit, session.Accepted{PID: "2001", User: "alice", Addr: "2001:db8::7", Port: "40022"}, true},
		{"forged by a local user", jsonForged, session.Accepted{}, false},
		{"binary message", jsonBinary, session.Accepted{}, false},
		{"a failure that mentions Accepted", jsonFailed, session.Accepted{}, false},
	}
	for _, c := range cases {
		e, ok := session.ParseJSON([]byte(c.line))
		if !ok {
			if c.ok && c.name != "binary message" {
				t.Errorf("%s: unparsable", c.name)
			}
			continue
		}
		a, ok := session.ParseAccepted(e)
		if ok != c.ok {
			t.Errorf("%s: accepted=%v", c.name, ok)
			continue
		}
		a.Time = time.Time{}
		if ok && a != c.want {
			t.Errorf("%s: %+v want %+v", c.name, a, c.want)
		}
	}
}

type fakeReader struct {
	entries []session.Entry
	err     error
	calls   int
	since   []time.Time
	limits  []int
}

func (f *fakeReader) Read(_ context.Context, since time.Time, limit int) ([]session.Entry, error) {
	f.calls++
	f.since = append(f.since, since)
	f.limits = append(f.limits, limit)
	return f.entries, f.err
}

func entryFor(line string) session.Entry {
	e, _ := session.ParseJSON([]byte(line))
	return e
}

// The follower hands only trustworthy, same-boot lines to the tracker, in
// bounded reads, and reports when the journal cannot be read.
func TestFollowerFeedsTheTrackerConservatively(t *testing.T) {
	now := time.Unix(1760000100, 0)
	tr := session.New(session.Options{Now: func() time.Time { return now }}, "boot-1")
	rd := &fakeReader{entries: []session.Entry{
		entryFor(jsonAccepted), entryFor(jsonForged),
		{Time: time.Unix(1760000002, 0), PID: "2001", Comm: "sshd", UID: "0", BootID: "boot-0", Message: "Accepted password for alice from 192.0.2.99 port 9 ssh2"},
	}}
	f := &session.Follower{Tracker: tr, Reader: rd, Now: func() time.Time { return now }, BootID: func() string { return "boot-1" }, Limit: 50}
	if err := f.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, j := tr.Len(); j != 1 {
		t.Fatalf("want only the one trustworthy line of this boot, got %d", j)
	}
	if rd.limits[0] != 50 || !rd.since[0].Equal(now.Add(-24*time.Hour)) {
		t.Errorf("the first read must be bounded: since=%v limit=%d", rd.since[0], rd.limits[0])
	}
	// A second poll re-reads with a short overlap and adds no duplicate.
	if err := f.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, j := tr.Len(); j != 1 {
		t.Errorf("a re-read line was duplicated: %d", j)
	}
	if !rd.since[1].After(rd.since[0]) {
		t.Errorf("the second read should start near the newest line, not the lookback again: %v", rd.since)
	}
}

func TestMissingJournalDisablesQuietlyAndRecovers(t *testing.T) {
	tr := session.New(session.Options{}, "b")
	rd := &fakeReader{err: errors.New("exec: journalctl: executable file not found in $PATH")}
	f := &session.Follower{Tracker: tr, Reader: rd, Every: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if st, why := f.Status(); st == session.JournalUnavailable && strings.Contains(why, "journalctl") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the unavailable state was not reported")
		}
		time.Sleep(time.Millisecond)
	}
	// Attribution from the audit log keeps working while the journal is down.
	r := newRig(t)
	r.login(0, "alice", 1000, 5, 2001, "203.0.113.9")
	if s := r.sudo(5, 1000, 5, "root", "id").Context.Session; s == nil || s.Confidence != model.ConfObserved {
		t.Errorf("audit attribution must not depend on the journal: %+v", s)
	}
	cancel()
	<-done
}

// A reader that hangs must not hold anything but its own goroutine.
func TestSlowJournalDoesNotBlockAttribution(t *testing.T) {
	tr := session.New(session.Options{}, "b")
	block := make(chan struct{})
	f := &session.Follower{Tracker: tr, Reader: blockingReader{block}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Run(ctx)
	defer close(block)

	done := make(chan struct{})
	go func() {
		c := &model.Context{LoginUID: "1000", SessionID: "5"}
		tr.Attribute(c, time.Now())
		tr.AddAccepted(nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("attribution waited for the journal")
	}
}

type blockingReader struct{ c chan struct{} }

func (b blockingReader) Read(ctx context.Context, _ time.Time, _ int) ([]session.Entry, error) {
	select {
	case <-b.c:
	case <-ctx.Done():
	}
	return nil, ctx.Err()
}

// journalctl is only ever asked to read, filtered by journald's own fields.
func TestExecReaderCommandIsReadOnlyAndFiltered(t *testing.T) {
	var gotName string
	var gotArgs []string
	r := session.ExecReader{Exec: func(_ context.Context, name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return []byte(jsonAccepted + "\n" + "not json\n" + jsonForged + "\n"), nil
	}}
	out, err := r.Read(context.Background(), time.Unix(1760000000, 0), 123)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(gotArgs, " ")
	for _, want := range []string{"--no-pager", "-o json", "-n 123", "--since @1760000000", "_UID=0", "_COMM=sshd", "_COMM=sshd-session"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	for _, bad := range []string{"--vacuum", "--rotate", "--flush", "--sync", "--setup-keys", "--follow", "-f "} {
		if strings.Contains(joined, bad) {
			t.Errorf("a command that is not a plain read: %q", bad)
		}
	}
	if gotName != "journalctl" || len(out) != 2 {
		t.Errorf("%s %d", gotName, len(out))
	}
}

// Many lines are cut by the limit, not read without bound.
func TestExecReaderStopsAtTheLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 500; i++ {
		b.WriteString(fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"1760000001000000","_PID":"%d","_COMM":"sshd","_UID":"0","MESSAGE":"Accepted password for u from 203.0.113.9 port 1 ssh2"}`+"\n", 100+i))
	}
	r := session.ExecReader{Exec: func(context.Context, string, ...string) ([]byte, error) { return []byte(b.String()), nil }}
	out, _ := r.Read(context.Background(), time.Unix(0, 0), 10)
	if len(out) != 10 {
		t.Errorf("read %d entries, want the limit 10", len(out))
	}
}

// Journal output never reaches logs: a message with a command-like tail is not
// stored anywhere but the parsed fields.
func TestNothingButParsedFieldsIsKept(t *testing.T) {
	tr := session.New(session.Options{}, "b")
	e := entryFor(`{"__REALTIME_TIMESTAMP":"1760000001000000","_PID":"2001","_COMM":"sshd","_UID":"0","MESSAGE":"Accepted password for alice from 203.0.113.9 port 51234 ssh2 -pSUPERSECRET"}`)
	a, ok := session.ParseAccepted(e)
	if !ok {
		t.Skip("trailing text is not an sshd format")
	}
	tr.AddAccepted([]session.Accepted{a})
	data := fmt.Sprintf("%+v", a)
	if strings.Contains(data, "SUPERSECRET") {
		t.Errorf("message text kept: %s", data)
	}
}
