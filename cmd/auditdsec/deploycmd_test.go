package main

import (
	"os"
	"strings"
	"testing"
)

// The fixtures are the output of the real `docker compose config --format json`
// for the file sets the installer builds (see docs/VERIFY.md); the checker is
// the installer's guard on what Compose would start. It reads configuration
// only: that Docker really starts these containers in these networks is shown
// by scripts/e2e/compose-consistency/run.sh.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/compose-" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestConsistentConfigurationsPass(t *testing.T) {
	cases := []struct {
		fixture string
		expect  DeployExpect
	}{
		{"domain", DeployExpect{Mode: "domain", UpstreamPort: "19477", HTTPSPort: "8443"}},
		{"selfsigned", DeployExpect{Mode: "selfsigned", UpstreamPort: "19477", HTTPSPort: "8443"}},
		{"ip", DeployExpect{Mode: "ip", UpstreamPort: "19477", HTTPSPort: "8443"}},
		{"tunnel", DeployExpect{Mode: "tunnel", UpstreamPort: "19477"}},
		{"enforce_control", DeployExpect{Mode: "domain", UpstreamPort: "19477", HTTPSPort: "8443", Enforce: true, Control: true}},
	}
	for _, c := range cases {
		problems, err := CheckDeployment(fixture(t, c.fixture), c.expect)
		if err != nil || len(problems) != 0 {
			t.Errorf("%s: %v %v", c.fixture, problems, err)
		}
	}
}

// Losing the proxy overlay is exactly what produced the 502: the agent comes
// back in a bridge network with its web server listening nowhere the proxy
// looks.
func TestLostOverlayIsDetectedWithTheActualValues(t *testing.T) {
	problems, err := CheckDeployment(fixture(t, "lost_overlay"), DeployExpect{Mode: "domain", UpstreamPort: "19477", HTTPSPort: "8443"})
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(problems, "\n")
	for _, want := range []string{
		`network_mode=""`,
		`listen on "", not on 127.0.0.1:19477`,
		"the proxy (caddy) is missing",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the diagnosis lacks %q:\n%s", want, text)
		}
	}
}

func TestEachDisagreementIsReported(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		expect  DeployExpect
		want    string
	}{
		{"wrong upstream port", "domain", DeployExpect{Mode: "domain", UpstreamPort: "9477", HTTPSPort: "8443"}, "not on 127.0.0.1:9477"},
		{"wrong public port", "domain", DeployExpect{Mode: "domain", UpstreamPort: "19477", HTTPSPort: "443"}, "not on 443"},
		{"a tunnel with a proxy", "domain", DeployExpect{Mode: "tunnel", UpstreamPort: "19477"}, "SSH tunnel"},
		{"a domain without certbot expected", "ip", DeployExpect{Mode: "domain", UpstreamPort: "19477", HTTPSPort: "8443"}, "certbot) is configured"},
		{"ip without certbot", "domain", DeployExpect{Mode: "ip", UpstreamPort: "19477", HTTPSPort: "8443"}, "certbot) is missing"},
		{"enforcement expected but absent", "domain", DeployExpect{Mode: "domain", UpstreamPort: "19477", HTTPSPort: "8443", Enforce: true}, "lacks NET_ADMIN"},
		{"enforcement present but off", "enforce_control", DeployExpect{Mode: "domain", UpstreamPort: "19477", HTTPSPort: "8443", Control: true}, "NET_ADMIN although blocking is off"},
		{"control expected but absent", "domain", DeployExpect{Mode: "domain", UpstreamPort: "19477", HTTPSPort: "8443", Control: true}, "no link to it"},
		{"control present but off", "enforce_control", DeployExpect{Mode: "domain", UpstreamPort: "19477", HTTPSPort: "8443", Enforce: true}, "although it is off"},
	}
	for _, c := range cases {
		got, err := CheckDeployment(fixture(t, c.fixture), c.expect)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(got, "\n"), c.want) {
			t.Errorf("%s: want a problem containing %q, got %v", c.name, c.want, got)
		}
	}
}

func TestPublishedAgentPortIsRefused(t *testing.T) {
	doc := strings.Replace(string(fixture(t, "domain")), `"auditdsec": {`, `"auditdsec": {"ports":[{"target":19477,"published":"19477"}],`, 1)
	got, err := CheckDeployment([]byte(doc), DeployExpect{Mode: "domain", UpstreamPort: "19477", HTTPSPort: "8443"})
	if err != nil || !strings.Contains(strings.Join(got, "\n"), "publishes ports") {
		t.Errorf("%v %v", got, err)
	}
}

func TestNotAComposeDocument(t *testing.T) {
	if _, err := CheckDeployment([]byte("nope"), DeployExpect{Mode: "domain"}); err == nil {
		t.Error("garbage must be an error, not a pass")
	}
	got, _ := CheckDeployment([]byte(`{"services":{}}`), DeployExpect{Mode: "domain"})
	if len(got) == 0 {
		t.Error("a configuration without the agent must not pass")
	}
}

func TestLoopbackOf(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:9477": "127.0.0.1:9477", ":9477": "127.0.0.1:9477", "0.0.0.0:80": "127.0.0.1:80", "[::]:81": "127.0.0.1:81", "[::1]:82": "[::1]:82",
	} {
		if got := loopbackOf(in); got != want {
			t.Errorf("loopbackOf(%q) = %q, want %q", in, got, want)
		}
	}
}
