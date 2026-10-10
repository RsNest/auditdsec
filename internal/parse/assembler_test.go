package parse

import (
	"testing"
	"time"
)

func TestAssemblerGroupsBySerialAndEOE(t *testing.T) {
	a := NewAssembler(time.Second)
	now := time.Unix(1760000300, 0)

	done, err := a.Add(`type=SYSCALL msg=audit(1760000300.400:800): auid=1000 uid=0 comm="vim" exe="/usr/bin/vim" key="ads_identity"`, now)
	if err != nil || len(done) != 0 {
		t.Fatalf("first record: done=%d err=%v", len(done), err)
	}
	done, err = a.Add(`type=PATH msg=audit(1760000300.400:800): item=0 name="/etc/passwd"`, now)
	if err != nil || len(done) != 0 {
		t.Fatalf("second record: done=%d err=%v", len(done), err)
	}
	done, err = a.Add(`type=EOE msg=audit(1760000300.400:800): `, now)
	if err != nil {
		t.Fatalf("EOE: %v", err)
	}
	if len(done) != 1 {
		t.Fatalf("EOE should complete the event, got %d events", len(done))
	}
	ev := done[0]
	if ev.Serial != 800 {
		t.Errorf("Serial = %d", ev.Serial)
	}
	if len(ev.Records) != 2 {
		t.Errorf("Records = %d, want 2 (EOE is not stored)", len(ev.Records))
	}
	if got := ev.Paths(); len(got) != 1 || got[0] != "/etc/passwd" {
		t.Errorf("Paths = %v", got)
	}
	if got := ev.AuditKeys(); len(got) != 1 || got[0] != "ads_identity" {
		t.Errorf("AuditKeys = %v", got)
	}
	if !ev.Has("SYSCALL") || !ev.Has("PATH") || ev.Has("USER_LOGIN") {
		t.Errorf("Types = %v", ev.Types())
	}
	if a.Pending() != 0 {
		t.Errorf("Pending = %d, want 0", a.Pending())
	}
}

func TestAssemblerSkipsJunk(t *testing.T) {
	a := NewAssembler(time.Second)
	now := time.Unix(1760000000, 0)
	if _, err := a.Add("", now); err == nil {
		t.Error("blank line should report ErrSkip")
	}
	if a.Pending() != 0 {
		t.Errorf("junk must not open an event, Pending = %d", a.Pending())
	}
}

func TestEventFieldHelpers(t *testing.T) {
	a := NewAssembler(time.Second)
	now := time.Unix(1760000000, 0)
	_, _ = a.Add(`type=SYSCALL msg=audit(1760000000.000:1): auid=1000 uid=0 comm="vim" key="ads_sshkeys"`, now)
	_, _ = a.Add(`type=PATH msg=audit(1760000000.000:1): item=0 name="/root/.ssh/authorized_keys"`, now)
	evs := a.Flush()
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]
	if got := ev.Field("comm"); got != "vim" {
		t.Errorf("Field(comm) = %q", got)
	}
	if got := ev.FieldOf("PATH", "name"); got != "/root/.ssh/authorized_keys" {
		t.Errorf("FieldOf(PATH,name) = %q", got)
	}
	if got := ev.FirstField("nope", "missing", "auid"); got != "1000" {
		t.Errorf("FirstField = %q", got)
	}
	if got := ev.FirstField("nope"); got != "" {
		t.Errorf("FirstField(missing) = %q", got)
	}
	if !ev.HasAny("PATH", "X") || ev.HasAny("X", "Y") {
		t.Error("HasAny is wrong")
	}
	if raw := ev.Raw(); raw == "" || len(ev.Types()) != 2 {
		t.Errorf("Raw/Types wrong: %q %v", raw, ev.Types())
	}
}
