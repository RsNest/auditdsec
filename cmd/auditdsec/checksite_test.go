package main

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func addrs(t *testing.T, in ...string) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, s := range in {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func report(t *testing.T, r siteReport) (string, verdict) {
	t.Helper()
	var b strings.Builder
	v := renderSiteReport(&b, r)
	return b.String(), v
}

func TestCheckSiteVerdicts(t *testing.T) {
	cases := []struct {
		name    string
		in      siteReport
		want    verdict
		mention []string
		absent  []string
	}{
		{
			name: "a public address can be certified",
			in:   siteReport{Input: "203.0.113.4", IP: netip.MustParseAddr("203.0.113.4")},
			want: verdictUsable,
			// It must say the certificate is short-lived and renewed, because
			// a six-day certificate looks like a bug if nobody said so.
			mention: []string{"IPv4", "shortlived", "six days", "port 80"},
		},
		{
			name:    "a public IPv6 address can be certified",
			in:      siteReport{Input: "2001:db8::1", IP: netip.MustParseAddr("2606:4700::1")},
			want:    verdictUsable,
			mention: []string{"IPv6"},
		},
		{
			name:    "a private address cannot",
			in:      siteReport{Input: "192.168.1.5", IP: netip.MustParseAddr("192.168.1.5")},
			want:    verdictUnusable,
			mention: []string{"not a public address", "self-signed"},
		},
		{
			name:    "a carrier-grade NAT address cannot",
			in:      siteReport{Input: "100.64.1.2", IP: netip.MustParseAddr("100.64.1.2")},
			want:    verdictUnusable,
			mention: []string{"not a public address"},
		},
		{
			name:    "a name that does not resolve",
			in:      siteReport{Input: "nope.example", ResolveErr: errors.New("no such host")},
			want:    verdictUnusable,
			mention: []string{"does not resolve", "AAAA"},
		},
		{
			name: "a name resolving only to private addresses",
			in:   siteReport{Input: "lan.example", V4: addrs(t, "10.0.0.5")},
			want: verdictUnusable,
		},
		{
			// Without being told the server's public address, the check cannot
			// know, and must say so instead of guessing from its own interfaces.
			name: "a name with no claimed address is undecided",
			in: siteReport{
				Input: "panel.example.com", V4: addrs(t, "203.0.113.4"),
				LocalHints: addrs(t, "172.17.0.2"), Private: true,
			},
			want:    verdictUnknown,
			mention: []string{"cannot tell", "container", "-public-ip", "preliminary" + ""},
			absent:  []string{"points here"},
		},
		{
			name: "a name matching the claimed address",
			in: siteReport{
				Input: "panel.example.com", V4: addrs(t, "203.0.113.4"),
				V6: addrs(t, "2606:4700::1"), Claimed: addrs(t, "203.0.113.4"),
			},
			want:    verdictUsable,
			mention: []string{"points here", "preliminary", "port 80"},
		},
		{
			name: "a name pointing somewhere else",
			in: siteReport{
				Input: "panel.example.com", V4: addrs(t, "198.51.100.9"),
				Claimed: addrs(t, "203.0.113.4"),
			},
			want:    verdictUnusable,
			mention: []string{"does NOT point"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text, got := report(t, c.in)
			if got != c.want {
				t.Errorf("verdict = %v, want %v\n%s", got, c.want, text)
			}
			for _, want := range c.mention {
				if !strings.Contains(text, want) {
					t.Errorf("the report does not mention %q:\n%s", want, text)
				}
			}
			for _, bad := range c.absent {
				if strings.Contains(text, bad) {
					t.Errorf("the report should not say %q:\n%s", bad, text)
				}
			}
		})
	}
}

// Both record types have to be shown: a server reachable only over IPv6 is a
// normal thing to deploy, and an AAAA-only name used to look like no DNS.
func TestCheckSiteShowsBothRecordTypes(t *testing.T) {
	text, v := report(t, siteReport{
		Input: "panel.example.com", V6: addrs(t, "2606:4700::1"),
		Claimed: addrs(t, "2606:4700::1"),
	})
	if v != verdictUsable {
		t.Fatalf("verdict = %v:\n%s", v, text)
	}
	if !strings.Contains(text, "AAAA  2606:4700::1") {
		t.Errorf("the AAAA record is not shown:\n%s", text)
	}
}

func TestPubliclyRoutable(t *testing.T) {
	public := []string{"203.0.113.4", "8.8.8.8", "2606:4700::1"}
	private := []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
		"100.64.0.1", "100.127.255.255", "169.254.1.1", "fd00::1", "0.0.0.0", "224.0.0.1",
	}
	for _, s := range public {
		if !publiclyRoutable(netip.MustParseAddr(s)) {
			t.Errorf("%s should be publicly routable", s)
		}
	}
	for _, s := range private {
		if publiclyRoutable(netip.MustParseAddr(s)) {
			t.Errorf("%s should not be publicly routable", s)
		}
	}
	// 100.x outside the carrier-grade range is ordinary public space.
	if !publiclyRoutable(netip.MustParseAddr("100.128.0.1")) {
		t.Error("100.128.0.1 is public space and was rejected")
	}
}
