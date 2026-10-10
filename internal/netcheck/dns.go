// Package netcheck answers the questions an installer has to settle before it
// publishes a panel on the internet: does this name point at this server, is
// this port free here, and — with the help of a machine elsewhere — can the
// world reach it. It uses the standard library only.
package netcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// DefaultResolvers are independent public DNS services asked directly over
// UDP, so the answer does not depend on /etc/hosts or on the local resolver's
// cache or on a split-horizon setup.
var DefaultResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// Resolver is one DNS source. Tests supply their own.
type Resolver interface {
	Name() string
	LookupIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

type udpResolver struct {
	addr string
	r    *net.Resolver
}

// NewUDPResolver asks one DNS server directly.
func NewUDPResolver(addr string) Resolver {
	d := &net.Dialer{Timeout: 3 * time.Second}
	return &udpResolver{addr: addr, r: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "udp", addr)
		},
	}}
}

func (u *udpResolver) Name() string { return u.addr }
func (u *udpResolver) LookupIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return u.r.LookupNetIP(ctx, network, host)
}
func (u *udpResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return u.r.LookupCNAME(ctx, host)
}

// Records is what one resolver said.
type Records struct {
	Resolver string
	V4, V6   []netip.Addr
	CNAME    string // the final name when the name is an alias
	Err      string
}

// DNSResult is what all resolvers said, and whether they agree.
type DNSResult struct {
	Name       string
	Per        []Records
	V4, V6     []netip.Addr // the union over the resolvers that answered
	Canonical  string
	Answered   int  // resolvers that gave an answer
	Consistent bool // every resolver that answered gave the same address sets
}

// NormalizeHost turns operator input into a bare ASCII host name: no scheme,
// no path, no port, no trailing dot, lower case, IDNA-encoded where the
// standard library can. It refuses anything that is not a plausible hostname,
// so nothing odd reaches a command line or a config file.
func NormalizeHost(in string) (string, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return "", errors.New("empty")
	}
	if strings.Contains(s, "://") || strings.ContainsAny(s, "/?#@ \t\r\n\\'\"`$;&|<>(){}*") {
		return "", errors.New("give the name only: no scheme, path, port or spaces")
	}
	if strings.Count(s, ":") > 0 {
		return "", errors.New("give the name only, without a port")
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if len(s) > 253 || s == "" {
		return "", errors.New("not a valid host name")
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("not a valid host name")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r > 127) {
				return "", errors.New("not a valid host name")
			}
		}
	}
	if !strings.Contains(s, ".") {
		return "", errors.New("a public name has at least two parts (panel.example.com)")
	}
	if allASCII(s) {
		return s, nil
	}
	return "", errors.New("internationalised names must be given in their xn-- form (the standard library cannot convert them)")
}

func allASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// LookupAll asks every resolver, retrying the whole round a few times while
// the answers are missing or disagree (DNS changes take time to spread).
func LookupAll(ctx context.Context, name string, rs []Resolver, attempts int, wait time.Duration) DNSResult {
	if attempts < 1 {
		attempts = 1
	}
	var res DNSResult
	for i := 0; i < attempts; i++ {
		res = lookupRound(ctx, name, rs)
		if res.Answered > 0 && res.Consistent {
			return res
		}
		if i < attempts-1 {
			select {
			case <-ctx.Done():
				return res
			case <-time.After(wait):
			}
		}
	}
	return res
}

func lookupRound(ctx context.Context, name string, rs []Resolver) DNSResult {
	res := DNSResult{Name: name}
	seen4, seen6 := map[netip.Addr]bool{}, map[netip.Addr]bool{}
	var sigs []string
	for _, r := range rs {
		c, cancel := context.WithTimeout(ctx, 6*time.Second)
		rec := Records{Resolver: r.Name()}
		v4, err4 := r.LookupIP(c, "ip4", name)
		v6, err6 := r.LookupIP(c, "ip6", name)
		if cn, err := r.LookupCNAME(c, name); err == nil {
			cn = strings.TrimSuffix(strings.ToLower(cn), ".")
			if cn != name {
				rec.CNAME = cn
			}
		}
		cancel()
		rec.V4, rec.V6 = unmap(v4), unmap(v6)
		// "no such record" for one family is a normal answer; failing to get
		// an answer for either is not.
		if err4 != nil && err6 != nil && !isNoData(err4) && !isNoData(err6) {
			rec.Err = err4.Error()
			res.Per = append(res.Per, rec)
			continue
		}
		res.Answered++
		for _, a := range rec.V4 {
			seen4[a] = true
		}
		for _, a := range rec.V6 {
			seen6[a] = true
		}
		if rec.CNAME != "" && res.Canonical == "" {
			res.Canonical = rec.CNAME
		}
		sigs = append(sigs, signature(rec))
		res.Per = append(res.Per, rec)
	}
	res.V4, res.V6 = keys(seen4), keys(seen6)
	res.Consistent = res.Answered > 0
	for _, s := range sigs {
		if s != sigs[0] {
			res.Consistent = false
		}
	}
	return res
}

func isNoData(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

func unmap(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		out = append(out, a.Unmap())
	}
	return out
}

func keys(m map[netip.Addr]bool) []netip.Addr {
	out := make([]netip.Addr, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func signature(r Records) string {
	f := func(as []netip.Addr) string {
		ss := make([]string, len(as))
		for i, a := range as {
			ss[i] = a.String()
		}
		sort.Strings(ss)
		return strings.Join(ss, ",")
	}
	return f(r.V4) + "|" + f(r.V6)
}

// Server is what is known about the machine itself.
type Server struct {
	// Global are public-looking addresses on this machine's interfaces.
	Global []netip.Addr
	// AnyPrivate is true when interfaces carry private addresses only, which
	// is what NAT and containers look like from inside.
	OnlyPrivate bool
	// Egress are the addresses an outside service saw this machine connect
	// from. A hint, not proof that inbound connections arrive here.
	Egress []netip.Addr
	// Claimed are addresses the operator stated.
	Claimed []netip.Addr
}

// Accepts reports whether an address is one this server is known or stated to
// have, and why.
func (s Server) Accepts(a netip.Addr) (bool, string) {
	for _, c := range s.Claimed {
		if c == a {
			return true, "stated by you"
		}
	}
	for _, g := range s.Global {
		if g == a {
			return true, "on this server's interface"
		}
	}
	for _, e := range s.Egress {
		if e == a {
			return true, "this server's outgoing address (a hint: inbound reachability is checked separately)"
		}
	}
	return false, ""
}

// DNSVerdict is the outcome of comparing records with the server.
type DNSVerdict struct {
	OK       bool
	Problems []string // what is wrong, in plain words
	Notes    []string // what matched and why
}

// JudgeDomain compares published records with this server. Every published
// address must lead here: one stray record is enough to break issuance or
// access for some visitors, so it is a stop, not a warning.
func JudgeDomain(res DNSResult, srv Server) DNSVerdict {
	var v DNSVerdict
	if res.Answered == 0 {
		v.Problems = append(v.Problems, fmt.Sprintf("none of the public DNS servers answered for %s (or the name does not exist)", res.Name))
		return v
	}
	if !res.Consistent {
		v.Problems = append(v.Problems, "the public DNS servers disagree, which usually means a recent change is still spreading: wait a few minutes and run the installer again")
		for _, r := range res.Per {
			v.Problems = append(v.Problems, fmt.Sprintf("  %s: A %s AAAA %s", r.Resolver, joinAddrs(r.V4), joinAddrs(r.V6)))
		}
	}
	if len(res.V4) == 0 && len(res.V6) == 0 {
		v.Problems = append(v.Problems, fmt.Sprintf("%s has no A or AAAA record in public DNS", res.Name))
		return v
	}
	known := len(srv.Global) + len(srv.Egress) + len(srv.Claimed)
	if known == 0 {
		v.Problems = append(v.Problems, "this server's own public address could not be determined (no public interface address and no outside answer); state it with --public-ip ADDRESS")
		return v
	}
	for _, a := range append(append([]netip.Addr{}, res.V4...), res.V6...) {
		if ok, why := srv.Accepts(a); ok {
			v.Notes = append(v.Notes, fmt.Sprintf("%s: %s", a, why))
			continue
		}
		fam, rec := "IPv4", "A"
		if a.Is6() {
			fam, rec = "IPv6", "AAAA"
		}
		v.Problems = append(v.Problems, fmt.Sprintf("%s record %s points to %s, which is not an address of this server (%s); a visitor or Let's Encrypt using it would reach another machine or none",
			rec, res.Name, a, fam))
	}
	if len(v.Problems) == 0 {
		v.OK = true
	}
	return v
}

func joinAddrs(as []netip.Addr) string {
	if len(as) == 0 {
		return "-"
	}
	ss := make([]string, len(as))
	for i, a := range as {
		ss[i] = a.String()
	}
	return strings.Join(ss, ",")
}

// Expected lists what the server is known to have, for the error message.
func (s Server) Expected() string {
	var all []netip.Addr
	all = append(all, s.Claimed...)
	all = append(all, s.Global...)
	all = append(all, s.Egress...)
	seen := map[netip.Addr]bool{}
	var out []string
	for _, a := range all {
		if !seen[a] {
			seen[a] = true
			out = append(out, a.String())
		}
	}
	return strings.Join(out, ", ")
}
