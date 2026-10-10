package parse

import (
	"testing"
	"time"
)

func feed(t *testing.T, a *Assembler, now time.Time, lines ...string) []*Event {
	t.Helper()
	var out []*Event
	for _, l := range lines {
		done, err := a.Add(l, now)
		if err != nil {
			t.Fatalf("Add(%q): %v", l, err)
		}
		out = append(out, done...)
	}
	return out
}

// Records of two events interleaved: SYSCALL(A) SYSCALL(B) PATH(A) EOE(A)
// PATH(B) EOE(B). Each event must come out whole, not as fragments.
func TestAssemblerInterleavedEvents(t *testing.T) {
	a := NewAssembler(time.Second)
	now := time.Unix(1760000000, 0)
	done := feed(t, a, now,
		`type=SYSCALL msg=audit(1760000000.100:10): syscall=257 success=yes key="ads_identity"`,
		`type=SYSCALL msg=audit(1760000000.101:11): syscall=257 success=yes key="ads_sshkeys"`,
		`type=PATH msg=audit(1760000000.100:10): item=0 name="/etc/passwd" nametype=NORMAL`,
		`type=EOE msg=audit(1760000000.100:10): `,
		`type=PATH msg=audit(1760000000.101:11): item=0 name="/root/.ssh/authorized_keys" nametype=NORMAL`,
		`type=EOE msg=audit(1760000000.101:11): `,
	)
	if len(done) != 2 {
		t.Fatalf("want 2 events, got %d", len(done))
	}
	for i, want := range []struct {
		serial int64
		path   string
	}{{10, "/etc/passwd"}, {11, "/root/.ssh/authorized_keys"}} {
		ev := done[i]
		if ev.Serial != want.serial || len(ev.Records) != 2 || ev.TargetPath() != want.path || !ev.Complete {
			t.Errorf("event %d: serial %d records %d path %q complete %v", i, ev.Serial, len(ev.Records), ev.TargetPath(), ev.Complete)
		}
	}
	if a.Pending() != 0 {
		t.Errorf("Pending = %d", a.Pending())
	}
}

// User-space records are whole events and close at once; they never wait
// for an EOE that does not exist.
func TestAssemblerStandaloneRecordsCloseAtOnce(t *testing.T) {
	a := NewAssembler(time.Hour)
	done := feed(t, a, time.Unix(1760000000, 0),
		`type=USER_LOGIN msg=audit(1760000000.000:1): msg='res=success'`,
		`type=USER_AUTH msg=audit(1760000000.000:2): msg='res=failed'`)
	if len(done) != 2 || !done[0].Complete || !done[1].Complete || a.Pending() != 0 {
		t.Fatalf("done %d pending %d", len(done), a.Pending())
	}
}

// A syscall event whose EOE never comes is closed by the timeout and marked
// incomplete; a lone non-syscall kernel record is complete. Neither blocks
// processing forever.
func TestAssemblerTimeoutMarksIncomplete(t *testing.T) {
	a := NewAssembler(500 * time.Millisecond)
	start := time.Unix(1760000000, 0)
	feed(t, a, start,
		`type=SYSCALL msg=audit(1760000000.000:1): syscall=2 success=yes key="ads_identity"`,
		`type=PATH msg=audit(1760000000.000:1): item=0 name="/etc/shadow"`,
		`type=CONFIG_CHANGE msg=audit(1760000000.000:2): op=remove_rule res=1`)
	if done := a.Expire(start.Add(100 * time.Millisecond)); len(done) != 0 {
		t.Fatalf("expired too early: %d", len(done))
	}
	done := a.Expire(start.Add(time.Second))
	if len(done) != 2 {
		t.Fatalf("Expire = %d events", len(done))
	}
	for _, ev := range done {
		switch ev.Serial {
		case 1:
			if ev.Complete || ev.IncompleteReason != IncompleteTimeout {
				t.Errorf("syscall without EOE: complete %v reason %q", ev.Complete, ev.IncompleteReason)
			}
		case 2:
			if !ev.Complete {
				t.Errorf("a lone CONFIG_CHANGE should be complete: %q", ev.IncompleteReason)
			}
		}
	}
}

// Shutdown flushes everything, each marked for what it is.
func TestAssemblerFlush(t *testing.T) {
	a := NewAssembler(time.Hour)
	feed(t, a, time.Unix(1760000000, 0), `type=SYSCALL msg=audit(1760000000.000:1): syscall=2`)
	done := a.Flush()
	if len(done) != 1 || done[0].IncompleteReason != IncompleteShutdown {
		t.Fatalf("Flush = %+v", done)
	}
	if len(a.Flush()) != 0 {
		t.Error("second Flush returned events")
	}
}

// The serial alone is not the identity: the same serial at another time (a
// rebooted kernel) is another event.
func TestAssemblerKeyIncludesTimestamp(t *testing.T) {
	a := NewAssembler(time.Second)
	done := feed(t, a, time.Unix(1760000000, 0),
		`type=SYSCALL msg=audit(1760000000.000:5): syscall=2 key="ads_identity"`,
		`type=SYSCALL msg=audit(1760009999.000:5): syscall=2 key="ads_identity"`,
		`type=EOE msg=audit(1760000000.000:5): `,
		`type=EOE msg=audit(1760009999.000:5): `)
	if len(done) != 2 || len(done[0].Records) != 1 || len(done[1].Records) != 1 {
		t.Fatalf("got %d events", len(done))
	}
}

// Over the limits nothing is lost silently: the oldest event is closed early
// and says why, and an oversized event keeps only its first records.
func TestAssemblerLimits(t *testing.T) {
	a := NewAssemblerWithLimits(time.Hour, Limits{MaxPending: 2, MaxRecords: 2, MaxBytes: 1 << 20})
	now := time.Unix(1760000000, 0)
	done := feed(t, a, now,
		`type=SYSCALL msg=audit(1760000000.000:1): syscall=2`,
		`type=SYSCALL msg=audit(1760000000.000:2): syscall=2`,
		`type=SYSCALL msg=audit(1760000000.000:3): syscall=2`)
	if len(done) != 1 || done[0].Serial != 1 || done[0].IncompleteReason != IncompletePending {
		t.Fatalf("pending cap: %+v", done)
	}
	feed(t, a, now,
		`type=PATH msg=audit(1760000000.000:3): item=0 name="/a"`,
		`type=PATH msg=audit(1760000000.000:3): item=1 name="/b"`)
	done = feed(t, a, now, `type=EOE msg=audit(1760000000.000:3): `)
	if len(done) != 1 || len(done[0].Records) != 2 || done[0].IncompleteReason != IncompleteRecords {
		t.Fatalf("record cap: %+v", done)
	}

	b := NewAssemblerWithLimits(time.Hour, Limits{MaxPending: 100, MaxRecords: 100, MaxBytes: 120})
	done = feed(t, b, now,
		`type=SYSCALL msg=audit(1760000000.000:1): syscall=2 comm="aaaaaaaaaaaaaaaa"`,
		`type=SYSCALL msg=audit(1760000000.000:2): syscall=2 comm="bbbbbbbbbbbbbbbb"`)
	if len(done) != 1 || done[0].Serial != 1 || done[0].IncompleteReason != IncompleteBytes {
		t.Fatalf("byte cap: %+v", done)
	}
}

// A record after its event's EOE does not quietly become a fragment.
func TestAssemblerLateRecord(t *testing.T) {
	a := NewAssembler(500 * time.Millisecond)
	start := time.Unix(1760000000, 0)
	feed(t, a, start,
		`type=SYSCALL msg=audit(1760000000.000:7): syscall=2`,
		`type=EOE msg=audit(1760000000.000:7): `,
		`type=PATH msg=audit(1760000000.000:7): item=0 name="/x"`)
	done := a.Expire(start.Add(time.Second))
	if len(done) != 1 || done[0].Complete || done[0].IncompleteReason != IncompleteLate {
		t.Fatalf("late: %+v", done)
	}
}

// The reader may save its position only up to the first line of an open event.
func TestAssemblerOldestOpen(t *testing.T) {
	a := NewAssembler(time.Hour)
	now := time.Unix(1760000000, 0)
	if _, ok := a.OldestOpen(); ok {
		t.Fatal("nothing is open")
	}
	_, _ = a.AddAt(`type=SYSCALL msg=audit(1760000000.000:1): syscall=2`, 100, now)
	_, _ = a.AddAt(`type=USER_LOGIN msg=audit(1760000000.000:9): msg='res=success'`, 150, now)
	_, _ = a.AddAt(`type=SYSCALL msg=audit(1760000000.000:2): syscall=2`, 200, now)
	if off, ok := a.OldestOpen(); !ok || off != 100 {
		t.Fatalf("OldestOpen = %d %v, want 100", off, ok)
	}
	_, _ = a.AddAt(`type=EOE msg=audit(1760000000.000:1): `, 260, now)
	if off, _ := a.OldestOpen(); off != 200 {
		t.Errorf("after the first closed: %d, want 200", off)
	}
}

// PATH selection: the created or deleted name wins over the parent directory
// whatever the record order; a relative name is resolved against CWD.
func TestTargetPath(t *testing.T) {
	a := NewAssembler(time.Second)
	done := feed(t, a, time.Unix(1760000000, 0),
		`type=SYSCALL msg=audit(1760000000.000:1): syscall=257 key="ads_sshkeys"`,
		`type=CWD msg=audit(1760000000.000:1): cwd="/root/.ssh"`,
		`type=PATH msg=audit(1760000000.000:1): item=0 name="authorized_keys" nametype=CREATE`,
		`type=PATH msg=audit(1760000000.000:1): item=1 name="/root/.ssh" nametype=PARENT`,
		`type=EOE msg=audit(1760000000.000:1): `)
	if len(done) != 1 {
		t.Fatal(len(done))
	}
	if got := done[0].TargetPath(); got != "/root/.ssh/authorized_keys" {
		t.Errorf("TargetPath = %q", got)
	}
}
