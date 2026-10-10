package netcheck

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// special-purpose blocks that are never a public server's address.
var special = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32",
	"fc00::/7", "fe80::/10", "ff00::/8",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// IsPublic reports whether an address could be a publicly routable server.
// Documentation ranges count as not public: nothing real lives there.
func IsPublic(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() {
		return false
	}
	for _, p := range special {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// LocalAddresses lists the addresses on this machine's interfaces. Inside a
// container with host networking these are the host's.
func LocalAddresses() []netip.Addr {
	var out []netip.Addr
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// Describe splits local addresses into public ones and notes whether only
// private ones exist.
func Describe(local []netip.Addr) (global []netip.Addr, onlyPrivate bool) {
	anyUsable := false
	for _, a := range local {
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
			continue
		}
		anyUsable = true
		if IsPublic(a) {
			global = append(global, a)
		}
	}
	return global, anyUsable && len(global) == 0
}

// EgressServices answer "what address am I connecting from?" in plain text.
// They are a hint only; the installer says so.
var EgressServices = map[string]string{
	"ip4": "https://api.ipify.org",
	"ip6": "https://api6.ipify.org",
}

// Egress asks the outside which addresses this machine connects from, per
// family. Failures are silent: the result is optional by design.
func Egress(ctx context.Context, services map[string]string) []netip.Addr {
	var out []netip.Addr
	for fam, u := range services {
		network := "tcp4"
		if fam == "ip6" {
			network = "tcp6"
		}
		c := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, addr)
			},
		}}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		if a, err := netip.ParseAddr(strings.TrimSpace(string(b))); err == nil && IsPublic(a) {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// ParseAddrs parses a comma or space separated address list.
func ParseAddrs(s string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		f = strings.Trim(f, "[]")
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, errors.New(f + " is not an IP address")
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}
