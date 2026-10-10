package auditlog

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCheckStates(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	log := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(log, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if st := Check(log, now, time.Hour); st.State != OK {
		t.Errorf("fresh log: %+v", st)
	}
	if st := Check(filepath.Join(dir, "missing"), now, time.Hour); st.State != Unavailable {
		t.Errorf("missing log: %+v", st)
	}
	if st := Check(dir, now, time.Hour); st.State != Unavailable {
		t.Errorf("a directory is not a log: %+v", st)
	}

	old := now.Add(-3 * time.Hour)
	if err := os.Chtimes(log, old, old); err != nil {
		t.Fatal(err)
	}
	st := Check(log, now, time.Hour)
	if st.State != Silent || st.LastWrite.IsZero() {
		t.Errorf("stale log: %+v", st)
	}
	if st := Check(log, now, 0); st.State != OK {
		t.Errorf("silence test disabled: %+v", st)
	}
}

func TestUnreadableLogIsUnavailableNotSilent(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("file permissions are not enforced here")
	}
	log := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(log, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(log, 0); err != nil {
		t.Fatal(err)
	}
	if st := Check(log, time.Now(), time.Hour); st.State != Unavailable {
		t.Errorf("unreadable log: %+v", st)
	}
}
