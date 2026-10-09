package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Inside a container os.Hostname() is the container id, so the host's own name
// has to come from somewhere else or every alert is labelled with a hex blob.
func TestResolveHost(t *testing.T) {
	dir := t.TempDir()
	mounted := filepath.Join(dir, "host-hostname")
	if err := os.WriteFile(mounted, []byte("web01.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := resolveHost("configured", mounted); got != "configured" {
		t.Errorf("the configured name must win: %q", got)
	}
	if got := resolveHost("  spaced  ", mounted); got != "spaced" {
		t.Errorf("the configured name should be trimmed: %q", got)
	}
	if got := resolveHost("", mounted); got != "web01.example.com" {
		t.Errorf("the mounted host name should be used: %q", got)
	}

	// No mount, so it falls back to the kernel's idea of the name.
	own, _ := os.Hostname()
	if got := resolveHost("", filepath.Join(dir, "absent")); got != own {
		t.Errorf("got %q, want the system host name %q", got, own)
	}
	if got := resolveHost("", ""); got != own {
		t.Errorf("got %q, want the system host name %q", got, own)
	}
}

func TestResolveHostIgnoresAnEmptyFile(t *testing.T) {
	mounted := filepath.Join(t.TempDir(), "host-hostname")
	if err := os.WriteFile(mounted, []byte("\n   \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	own, _ := os.Hostname()
	if got := resolveHost("", mounted); got != own {
		t.Errorf("an empty file should be ignored, got %q", got)
	}
}

func TestConfigPathPrefersTheFlag(t *testing.T) {
	t.Setenv("AUDITDSEC_CONFIG", "/from/env.yaml")
	if got := configPath("/from/flag.yaml"); got != "/from/flag.yaml" {
		t.Errorf("got %q", got)
	}
	if got := configPath(""); got != "/from/env.yaml" {
		t.Errorf("got %q", got)
	}
}
