// Package netaddr gives every layer of the agent — detector, store, Telegram,
// panel, firewall — one identity for an address. Strings are not addresses:
// "2001:DB8::1", "2001:db8:0:0:0:0:0:1" and "::ffff:203.0.113.7" against
// "203.0.113.7" are the same machine written differently, and a ban or an
// allowlist entry that compares text protects against nothing.
package netaddr

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Class says what kind of address it is, for the one policy about which of
// them may be blocked.
type Class string

const (
	Public      Class = "public"
	Private     Class = "private"     // RFC 1918, IPv6 unique local
	Loopback    Class = "loopback"    // 127.0.0.0/8, ::1
	LinkLocal   Class = "link_local"  // 169.254.0.0/16, fe80::/10
	Multicast   Class = "multicast"   // and the IPv4 broadcast address
	Unspecified Class = "unspecified" // 0.0.0.0, ::
)

// Parse reads one plain address and returns it in canonical form: IPv4-mapped
// IPv6 becomes IPv4, no zone, the shortest lower-case IPv6 text.
func Parse(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", clip(s))
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%q has a zone; use the plain address", clip(s))
	}
	return a.Unmap(), nil
}

// Canon is Parse returning the canonical text.
func Canon(s string) (string, error) {
	a, err := Parse(s)
	if err != nil {
		return "", err
	}
	return a.String(), nil
}

// Classify reports what kind of address a is.
func Classify(a netip.Addr) Class {
	a = a.Unmap()
	switch {
	case a.IsUnspecified():
		return Unspecified
	case a.IsLoopback():
		return Loopback
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast():
		return LinkLocal
	case a.IsMulticast() || (a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255})):
		return Multicast
	case a.IsPrivate():
		return Private
	}
	return Public
}

// Smallest prefixes an allowlist entry may cover. A typo that trusts the
// whole internet silently switches blocking off, so it is refused.
const (
	minBits4 = 8
	minBits6 = 16
)

// Entry is an allowlist entry: one address, or a network.
type Entry struct {
	Addr   netip.Addr   // set for a single address
	Prefix netip.Prefix // set for a network
}

// IsNetwork reports whether the entry is a prefix rather than one address.
func (e Entry) IsNetwork() bool { return e.Prefix.IsValid() }

// String is the canonical text and the key under which the entry is stored.
func (e Entry) String() string {
	if e.IsNetwork() {
		return e.Prefix.String()
	}
	return e.Addr.String()
}

// Contains reports whether a is the entry's address or inside its network.
func (e Entry) Contains(a netip.Addr) bool {
	a = a.Unmap()
	if e.IsNetwork() {
		return e.Prefix.Contains(a)
	}
	return e.Addr == a
}

// ParseEntry reads an address or a CIDR network. A network is masked to its
// base ("203.0.113.9/24" becomes "203.0.113.0/24"); a /32 or /128 is the
// single address.
func ParseEntry(s string) (Entry, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := Parse(s)
		return Entry{Addr: a}, err
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return Entry{}, fmt.Errorf("%q is not an address or a CIDR network", clip(s))
	}
	if p.Addr().Zone() != "" {
		return Entry{}, errors.New("a network with a zone is not accepted")
	}
	a := p.Addr().Unmap()
	bits := p.Bits()
	if p.Addr().Is4In6() {
		bits -= 96
	}
	if bits < 0 {
		return Entry{}, fmt.Errorf("%q is not a valid network", clip(s))
	}
	p = netip.PrefixFrom(a, bits)
	if p.Bits() == a.BitLen() {
		return Entry{Addr: a}, nil
	}
	min := minBits6
	if a.Is4() {
		min = minBits4
	}
	if p.Bits() < min {
		return Entry{}, fmt.Errorf("%s is too wide: an allowlist network must be at least /%d for %s", p, min, family(a))
	}
	return Entry{Prefix: p.Masked()}, nil
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}
