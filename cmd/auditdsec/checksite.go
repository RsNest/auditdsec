package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

// errCheckFailed makes a check command exit non-zero without printing
// anything more: the explanation is already on stdout, in full sentences.
var errCheckFailed = errors.New("")

// verdict is how much the check could establish. It deliberately has a third
// value: the common case on a server behind NAT is that nothing here can tell
// whether issuance will work, and saying so is more useful than guessing.
type verdict int

const (
	verdictUsable verdict = iota
	verdictUnknown
	verdictUnusable
)

// siteReport is everything the check found, separated from how it is printed
// so the wording can be tested without a network.
type siteReport struct {
	Input string
	// IP is set when the input was an address rather than a name.
	IP netip.Addr
	// V4 and V6 are the A and AAAA records of a name.
	V4, V6 []netip.Addr
	// ResolveErr is a name that does not resolve at all.
	ResolveErr error
	// Claimed are the addresses the operator passed with -public-ip. They are
	// the only addresses this program can treat as "the server's", because it
	// may well be running inside a container with an address of its own.
	Claimed []netip.Addr
	// LocalHints are the addresses of this machine's interfaces. They are a
	// hint and nothing more.
	LocalHints []netip.Addr
	// Private is true when every local address is private, which is what a
	// container or a NAT looks like from in here.
	Private bool
}

func cmdCheckSite(args []string) error {
	var claimed multiAddr
	fs := flag.NewFlagSet("check-site", flag.ContinueOnError)
	fs.Var(&claimed, "public-ip", "this server's public address, as seen from the internet (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, "Usage:\n"+
			"  auditdsec check-site panel.example.com [-public-ip 203.0.113.4]\n"+
			"  auditdsec check-site 203.0.113.4\n")
		return fmt.Errorf("expected one domain or address")
	}

	r := siteReport{Input: strings.TrimSuffix(strings.TrimSpace(fs.Arg(0)), "."), Claimed: claimed}
	r.LocalHints, r.Private = localAddresses()

	if addr, err := netip.ParseAddr(r.Input); err == nil {
		r.IP = addr.Unmap()
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		v4, err4 := net.DefaultResolver.LookupNetIP(ctx, "ip4", r.Input)
		v6, err6 := net.DefaultResolver.LookupNetIP(ctx, "ip6", r.Input)
		r.V4, r.V6 = unmapAll(v4), unmapAll(v6)
		if len(r.V4) == 0 && len(r.V6) == 0 {
			r.ResolveErr = firstErr(err4, err6)
		}
	}

	if renderSiteReport(os.Stdout, r) == verdictUnusable {
		return errCheckFailed
	}
	return nil
}

// renderSiteReport writes the report and returns how it came out.
func renderSiteReport(w io.Writer, r siteReport) verdict {
	if r.IP.IsValid() {
		return renderAddress(w, r)
	}
	return renderName(w, r)
}

func renderAddress(w io.Writer, r siteReport) verdict {
	fmt.Fprintf(w, "%s is an address, not a name.\n\n", r.Input)
	if !publiclyRoutable(r.IP) {
		fmt.Fprintf(w, "It is not a public address, so no certificate authority will certify it.\n"+
			"Use the address your provider gave you, a domain, or the self-signed option\n"+
			"(./install.sh offers all three).\n")
		return verdictUnusable
	}
	kind := "IPv4"
	if r.IP.Is6() {
		kind = "IPv6"
	}
	fmt.Fprintf(w, "It is a public %s address, and Let's Encrypt does certify those, under the\n"+
		"shortlived profile: the certificate lasts about six days and is renewed for you\n"+
		"several times a week.\n\nStill to be true, and not checkable from here:\n"+
		"  - this address really reaches this server from the internet\n"+
		"  - port 80 is open and nothing else is using it (the renewal uses it)\n"+
		"  - port 443 is open\n\n"+
		"Run ./install.sh and choose the public-address option.\n", kind)
	writeLocalHint(w, r)
	return verdictUsable
}

func renderName(w io.Writer, r siteReport) verdict {
	if r.ResolveErr != nil {
		fmt.Fprintf(w, "%s does not resolve: %v\n\n"+
			"Add an A record (IPv4) or an AAAA record (IPv6) pointing at this server,\n"+
			"wait for it to take effect, then run this again.\n", r.Input, r.ResolveErr)
		return verdictUnusable
	}
	fmt.Fprintf(w, "%s resolves to:\n", r.Input)
	for _, a := range r.V4 {
		fmt.Fprintf(w, "  A     %s\n", a)
	}
	for _, a := range r.V6 {
		fmt.Fprintf(w, "  AAAA  %s\n", a)
	}

	resolved := append(append([]netip.Addr{}, r.V4...), r.V6...)
	if public := filter(resolved, publiclyRoutable); len(public) == 0 {
		fmt.Fprintf(w, "\nNone of those are public addresses, so Let's Encrypt cannot reach the name\n"+
			"and will not issue a certificate for it.\n")
		return verdictUnusable
	}

	if len(r.Claimed) > 0 {
		fmt.Fprintf(w, "\nyou told me this server is at: %s\n", joinAddrs(r.Claimed))
		if intersects(resolved, r.Claimed) {
			fmt.Fprintf(w, "\nThe name points here. That is the part that usually goes wrong, so this is\n"+
				"a good sign.\n")
			writeIssuanceCaveats(w)
			return verdictUsable
		}
		fmt.Fprintf(w, "\nThe name does NOT point at any of those addresses, so issuance would fail.\n"+
			"Fix the DNS record, or use the address itself, or the self-signed option.\n")
		return verdictUnusable
	}

	fmt.Fprintf(w, "\nWhether that is this server, I cannot tell from in here: this process may be\n"+
		"inside a container or behind NAT, so the addresses it can see are not the\n"+
		"server's public ones.\n")
	writeLocalHint(w, r)
	fmt.Fprintf(w, "\nTo have this checked, pass the address your provider gave you:\n"+
		"  auditdsec check-site %s -public-ip <your server's public address>\n", r.Input)
	writeIssuanceCaveats(w)
	return verdictUnknown
}

func writeLocalHint(w io.Writer, r siteReport) {
	if len(r.LocalHints) == 0 {
		return
	}
	fmt.Fprintf(w, "\nFor reference, the interfaces visible to this process: %s\n", joinAddrs(r.LocalHints))
	if r.Private {
		fmt.Fprint(w, "All of them are private, which is what a container or a NAT looks like.\n"+
			"They say nothing about the server's public address.\n")
	}
}

func writeIssuanceCaveats(w io.Writer) {
	fmt.Fprint(w, "\nThis is a preliminary check, not a guarantee: a certificate is issued only if\n"+
		"all of this also holds, none of which can be checked from here:\n"+
		"  - the DNS record has taken effect everywhere, not only for this resolver\n"+
		"  - port 80 is open from the internet, and reaches this server\n"+
		"  - port 443 is open\n"+
		"  - no firewall or provider filter is in the way\n\n"+
		"./install.sh goes on to request the certificate and tells you if it fails.\n")
}

// localAddresses lists this machine's non-loopback addresses, and reports
// whether every one of them is private.
func localAddresses() ([]netip.Addr, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, false
	}
	var out []netip.Addr
	public := false
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
				continue
			}
			out = append(out, addr)
			if publiclyRoutable(addr) {
				public = true
			}
		}
	}
	return out, len(out) > 0 && !public
}

// publiclyRoutable reports whether a certificate authority could reach the
// address. Go's IsPrivate covers RFC 1918 and IPv6 unique-local; carrier-grade
// NAT is not private by that definition but is just as unreachable.
func publiclyRoutable(a netip.Addr) bool {
	if !a.IsValid() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() && a.As4()[0] == 100 && a.As4()[1] >= 64 && a.As4()[1] <= 127 {
		return false // 100.64.0.0/10, carrier-grade NAT
	}
	return true
}

func filter(in []netip.Addr, keep func(netip.Addr) bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range in {
		if keep(a) {
			out = append(out, a)
		}
	}
	return out
}

func intersects(a, b []netip.Addr) bool {
	for _, x := range a {
		for _, y := range b {
			if x.Unmap() == y.Unmap() {
				return true
			}
		}
	}
	return false
}

func unmapAll(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		out = append(out, a.Unmap())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func joinAddrs(in []netip.Addr) string {
	parts := make([]string, 0, len(in))
	for _, a := range in {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return errors.New("no A or AAAA record")
}

// multiAddr collects a repeatable -public-ip flag.
type multiAddr []netip.Addr

func (m *multiAddr) String() string { return joinAddrs(*m) }

func (m *multiAddr) Set(v string) error {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%q is not an address", v)
	}
	*m = append(*m, a.Unmap())
	return nil
}
