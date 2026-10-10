package logging

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRotatingFileRotatesAndKeepsBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")

	r, err := NewRotatingFile(path, 1, 2) // 1 MB, two backups
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.maxBytes = 100 // shrink so the test does not write megabytes

	for i := 0; i < 12; i++ {
		if _, err := r.Write([]byte(strings.Repeat("x", 40) + "\n")); err != nil {
			t.Fatal(err)
		}
	}

	for _, name := range []string{"agent.log", "agent.log.1", "agent.log.2"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s should exist: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.log.3")); !os.IsNotExist(err) {
		t.Error("agent.log.3 should have been dropped")
	}
}

func TestRotatingFileWithoutBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	r, err := NewRotatingFile(path, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.maxBytes = 50

	for i := 0; i < 5; i++ {
		if _, err := r.Write([]byte(strings.Repeat("y", 30) + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Error("no backup should be kept when max_backups is zero")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 50 {
		t.Errorf("the live file grew to %d bytes", fi.Size())
	}
}

func TestRotatingFileAppendsToExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	r, err := NewRotatingFile(path, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}
	r.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old\nnew\n" {
		t.Errorf("content = %q", b)
	}
}

func TestWriteAfterCloseFails(t *testing.T) {
	r, err := NewRotatingFile(filepath.Join(t.TempDir(), "a.log"), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if _, err := r.Write([]byte("x")); err == nil {
		t.Error("writing to a closed file should fail")
	}
}

func TestSetupWritesJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	log, closer, err := Setup(Options{File: path, Level: "debug", MaxSizeMB: 1, MaxBackups: 1})
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hello", "answer", 42)
	if closer != nil {
		closer.Close()
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"msg":"hello"`) || !strings.Contains(string(b), `"answer":42`) {
		t.Errorf("log line = %q", b)
	}
}

// An unwritable log path must not stop the agent: it keeps logging to stdout.
func TestSetupSurvivesUnwritableFile(t *testing.T) {
	skipOnWindows(t)
	log, closer, err := Setup(Options{File: "/proc/definitely/not/writable/a.log", Level: "info"})
	if err != nil {
		t.Fatalf("Setup should not fail: %v", err)
	}
	if closer != nil {
		t.Error("no file should have been opened")
	}
	log.Info("still logging")
}

func TestParseLevel(t *testing.T) {
	tests := map[string]slog.Level{
		"debug":    slog.LevelDebug,
		"info":     slog.LevelInfo,
		"WARN":     slog.LevelWarn,
		"warning":  slog.LevelWarn,
		"error":    slog.LevelError,
		"":         slog.LevelInfo,
		"nonsense": slog.LevelInfo,
	}
	for in, want := range tests {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

// The agent reads the Linux audit log; these tests rely on POSIX semantics
// (renaming or truncating a file that is still open, /proc paths).
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file semantics required")
	}
}
