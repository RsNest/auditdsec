package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RsNest/auditdsec/internal/api"
	"github.com/RsNest/auditdsec/internal/config"
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

// The link is what the person needs after installing, so it must be right in
// both shapes: behind a proxy, and reachable only through a tunnel.
func TestPrintPanelBanner(t *testing.T) {
	cfg := config.Defaults(config.ProfileSimple)
	cfg.Web.Listen, cfg.Web.Login = "127.0.0.1:9477", "admin"

	var local strings.Builder
	printPanelBanner(&local, cfg, api.StateBootstrap)
	for _, want := range []string{"http://127.0.0.1:9477", "admin / admin", "ssh -L 9477:127.0.0.1:9477"} {
		if !strings.Contains(local.String(), want) {
			t.Errorf("the loopback banner does not mention %q:\n%s", want, local.String())
		}
	}

	cfg.Web.PublicURL = "https://panel.example.com"
	var public strings.Builder
	printPanelBanner(&public, cfg, api.StateReady)
	if !strings.Contains(public.String(), "https://panel.example.com") {
		t.Errorf("the banner does not show the public address:\n%s", public.String())
	}
	if strings.Contains(public.String(), "ssh -L") {
		t.Errorf("the banner offers a tunnel for a panel that is already published:\n%s", public.String())
	}
}

// After setup the banner must not name admin, nor a login from the
// environment that the owner may have replaced in the panel.
func TestBannerAfterSetupDoesNotOfferTheDefaultPair(t *testing.T) {
	cfg := config.Defaults(config.ProfileSimple)
	cfg.Web.Listen, cfg.Web.Login, cfg.Web.PublicURL = "127.0.0.1:9477", "admin", "https://panel.example.com:27431"
	var b strings.Builder
	printPanelBanner(&b, cfg, api.StateReady)
	if strings.Contains(b.String(), "admin") || !strings.Contains(b.String(), "https://panel.example.com:27431") {
		t.Errorf("banner:\n%s", b.String())
	}
	b.Reset()
	printPanelBanner(&b, cfg, api.StateLocked)
	if !strings.Contains(b.String(), "STOPPED") {
		t.Errorf("locked banner:\n%s", b.String())
	}
}
