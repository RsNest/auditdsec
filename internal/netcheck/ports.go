package netcheck

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// BindResult is the outcome of trying to listen on one port on one address
// family.
type BindResult struct {
	Family string // tcp4 | tcp6
	OK     bool
	Busy   bool // the address is taken
	Denied bool // not allowed to bind (a low port without privilege)
	Skip   bool // this family does not exist here (no IPv6)
	Err    string
}

// Bind tries to listen on the wildcard address of each family and lets go at
// once. It answers "could the proxy bind this", and says nothing about the
// firewall or about the outside.
func Bind(port int) []BindResult {
	var out []BindResult
	for _, f := range []struct{ network, addr string }{
		{"tcp4", "0.0.0.0"}, {"tcp6", "[::]"},
	} {
		r := BindResult{Family: f.network}
		l, err := net.Listen(f.network, f.addr+":"+strconv.Itoa(port))
		switch {
		case err == nil:
			l.Close()
			r.OK = true
		case errors.Is(err, syscall.EADDRINUSE):
			r.Busy, r.Err = true, "address already in use"
		case errors.Is(err, syscall.EACCES):
			r.Denied, r.Err = true, "permission denied"
		case errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EPROTONOSUPPORT):
			r.Skip, r.Err = true, "not available on this machine"
		default:
			r.Err = err.Error()
		}
		out = append(out, r)
	}
	return out
}

// Usable reports whether the port can be bound on every family that exists,
// and at least one does.
func Usable(rs []BindResult) bool {
	any := false
	for _, r := range rs {
		if r.Skip {
			continue
		}
		if !r.OK {
			return false
		}
		any = true
	}
	return any
}

// Describe renders a failed bind in words.
func DescribeBind(port int, rs []BindResult) string {
	var parts []string
	for _, r := range rs {
		switch {
		case r.OK, r.Skip:
		case r.Busy:
			parts = append(parts, fmt.Sprintf("%s: port %d is already in use", r.Family, port))
		case r.Denied:
			parts = append(parts, fmt.Sprintf("%s: not allowed to bind port %d", r.Family, port))
		default:
			parts = append(parts, fmt.Sprintf("%s: %s", r.Family, r.Err))
		}
	}
	return strings.Join(parts, "; ")
}

// EphemeralRange reads the range the kernel hands out for outgoing
// connections, so that a published port is not picked from it.
func EphemeralRange() (lo, hi int) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err == nil {
		f := strings.Fields(string(b))
		if len(f) == 2 {
			l, e1 := strconv.Atoi(f[0])
			h, e2 := strconv.Atoi(f[1])
			if e1 == nil && e2 == nil && l > 0 && h >= l {
				return l, h
			}
		}
	}
	return 32768, 60999
}

// Candidates returns the ports to try for an automatic choice: first (443),
// then up to n distinct random ones from [lo, hi] that are not excluded and
// not in the kernel's ephemeral range.
func Candidates(first, n, lo, hi int, exclude map[int]bool, rng *rand.Rand) []int {
	out := []int{first}
	elo, ehi := EphemeralRange()
	var pool []int
	for p := lo; p <= hi; p++ {
		if exclude[p] || p == first || (p >= elo && p <= ehi) {
			continue
		}
		pool = append(pool, p)
	}
	rng.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	if len(pool) > n {
		pool = pool[:n]
	}
	return append(out, pool...)
}
