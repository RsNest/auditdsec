package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/RsNest/auditdsec/internal/netcheck"
)

// The commands below are what ./install.sh asks before it publishes a panel.
// They print KEY=VALUE lines on standard output for the script and sentences on
// standard error for the person, and use the exit status for the verdict.
// None of them prints a secret.

const (
	exitMismatch    = 3
	exitNotReach    = 4
	exitUnavailable = 5
)

type exitCode int

func (e exitCode) Error() string { return "" }

func kv(k string, v ...string) { fmt.Printf("%s=%s\n", k, strings.Join(v, ",")) }

func addrStrings(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

func cmdNetCheck(args []string) error {
	if len(args) == 0 || (args[0] != "domain" && args[0] != "ip") {
		return errors.New("usage: auditdsec net-check domain NAME | net-check ip   [-public-ip A,B] [-no-egress]")
	}
	kind, args := args[0], args[1:]
	var name string
	if kind == "domain" {
		if len(args) == 0 {
			return errors.New("net-check domain: give the name")
		}
		name, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("net-check", flag.ContinueOnError)
	claimed := fs.String("public-ip", "", "this server's public address(es), if you know them")
	noEgress := fs.Bool("no-egress", os.Getenv("PANEL_NO_EGRESS") == "1", "do not ask an outside service which address this machine connects from")
	attempts := fs.Int("attempts", 3, "DNS rounds while answers are missing or disagree")
	wait := fs.Duration("wait", 5*time.Second, "pause between DNS rounds")
	resolvers := fs.String("resolvers", os.Getenv("PANEL_DNS_RESOLVERS"), "comma separated DNS servers host:port (default: three public ones)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	srv := netcheck.Server{}
	var err error
	if srv.Claimed, err = netcheck.ParseAddrs(*claimed); err != nil {
		return err
	}
	var onlyPrivate bool
	srv.Global, onlyPrivate = netcheck.Describe(netcheck.LocalAddresses())
	srv.OnlyPrivate = onlyPrivate
	if !*noEgress {
		srv.Egress = netcheck.Egress(ctx, netcheck.EgressServices)
	}

	if kind == "ip" {
		seen := map[netip.Addr]bool{}
		var cands []netip.Addr
		// What the operator stated is taken as it is (a lab or an odd network may
		// use an address this program would not call public); what was found is
		// kept only if it could be public.
		for i, group := range [][]netip.Addr{srv.Claimed, srv.Global, srv.Egress} {
			for _, a := range group {
				if !seen[a] && (i == 0 || netcheck.IsPublic(a)) {
					seen[a] = true
					cands = append(cands, a)
				}
			}
		}
		onIface := map[netip.Addr]bool{}
		for _, g := range srv.Global {
			onIface[g] = true
		}
		nat := false
		for _, e := range srv.Egress {
			if !onIface[e] {
				nat = true
			}
		}
		kv("CANDIDATES", addrStrings(cands)...)
		kv("NAT", yesno(nat || onlyPrivate))
		kv("AMBIGUOUS", yesno(len(cands) > 1))
		if len(cands) == 0 {
			fmt.Fprintln(os.Stderr, "No public address of this server was found. State it with --public-ip ADDRESS.")
			return exitCode(exitMismatch)
		}
		if nat {
			fmt.Fprintln(os.Stderr, "Note: the address seen from outside is not on any of this machine's interfaces (NAT or a floating address).")
			fmt.Fprintln(os.Stderr, "Whether connections to it reach this machine is only known after the external check.")
		}
		return nil
	}

	host, err := netcheck.NormalizeHost(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return exitCode(exitMismatch)
	}
	var rs []netcheck.Resolver
	list := netcheck.DefaultResolvers
	if *resolvers != "" {
		list = strings.Split(*resolvers, ",")
	}
	for _, r := range list {
		rs = append(rs, netcheck.NewUDPResolver(strings.TrimSpace(r)))
	}
	res := netcheck.LookupAll(ctx, host, rs, *attempts, *wait)
	v := netcheck.JudgeDomain(res, srv)
	kv("NAME", host)
	kv("A", addrStrings(res.V4)...)
	kv("AAAA", addrStrings(res.V6)...)
	if res.Canonical != "" {
		kv("CNAME", res.Canonical)
	}
	kv("SERVER", srv.Expected())
	if !v.OK {
		kv("VERDICT", "mismatch")
		fmt.Fprintf(os.Stderr, "DNS for %s does not lead to this server:\n", host)
		for _, p := range v.Problems {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
		}
		fmt.Fprintf(os.Stderr, "Public DNS says: A %s   AAAA %s\n", orDash(addrStrings(res.V4)), orDash(addrStrings(res.V6)))
		fmt.Fprintf(os.Stderr, "This server's addresses: %s\n", orDash(strings.Split(srv.Expected(), ", ")))
		fmt.Fprintln(os.Stderr, "Fix the records so every A/AAAA leads here (remove a wrong AAAA rather than leave it), wait for DNS to spread, then run ./install.sh again.")
		fmt.Fprintln(os.Stderr, "A CDN or proxy in front of the name is not supported in direct mode: use a DNS-only record.")
		return exitCode(exitMismatch)
	}
	kv("VERDICT", "ok")
	kv("FAMILIES", familyList(res)...)
	for _, n := range v.Notes {
		fmt.Fprintf(os.Stderr, "  %s\n", n)
	}
	return nil
}

func familyList(r netcheck.DNSResult) []string {
	var out []string
	if len(r.V4) > 0 {
		out = append(out, "4")
	}
	if len(r.V6) > 0 {
		out = append(out, "6")
	}
	return out
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(s []string) string {
	if len(s) == 0 || (len(s) == 1 && s[0] == "") {
		return "-"
	}
	return strings.Join(s, ", ")
}

// cmdPortPlan lists the ports an automatic choice tries, in order.
func cmdPortPlan(args []string) error {
	fs := flag.NewFlagSet("port-plan", flag.ContinueOnError)
	first := fs.Int("first", 443, "tried first")
	n := fs.Int("n", 16, "how many random fallbacks")
	lo := fs.Int("lo", 20000, "lowest random port")
	hi := fs.Int("hi", 29999, "highest random port")
	exclude := fs.String("exclude", "", "comma separated ports never to pick (upstream, admin API, ...)")
	seed := fs.Int64("seed", 0, "random seed (tests); 0 = random")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ex := map[int]bool{80: true, 2019: true}
	for _, f := range strings.Split(*exclude, ",") {
		if p, err := strconv.Atoi(strings.TrimSpace(f)); err == nil {
			ex[p] = true
		}
	}
	if *seed == 0 {
		*seed = time.Now().UnixNano()
	}
	for _, p := range netcheck.Candidates(*first, *n, *lo, *hi, ex, rand.New(rand.NewSource(*seed))) {
		fmt.Println(p)
	}
	return nil
}

// cmdPortCheck tries to bind the port on both address families.
func cmdPortCheck(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: auditdsec port-check PORT")
	}
	p, err := strconv.Atoi(args[0])
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("%q is not a port (1-65535)", args[0])
	}
	rs := netcheck.Bind(p)
	kv("PORT", args[0])
	if netcheck.Usable(rs) {
		kv("BIND", "ok")
		return nil
	}
	kv("BIND", "unavailable")
	kv("REASON", netcheck.DescribeBind(p, rs))
	return exitCode(exitMismatch)
}

// cmdProbeListen is the temporary listener: it exists only to be reached by
// the external check and serves one fixed string.
func cmdProbeListen(args []string) error {
	fs := flag.NewFlagSet("probe-listen", flag.ContinueOnError)
	port := fs.Int("port", 0, "port to listen on (all addresses)")
	ttl := fs.Duration("ttl", 3*time.Minute, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return err
	}
	nonce := os.Getenv("AUDITDSEC_PROBE_NONCE") // not an argument: it would show in a process list
	if *port < 1 || *port > 65535 || len(nonce) < 16 {
		return errors.New("probe-listen needs -port and AUDITDSEC_PROBE_NONCE (16+ letters or digits)")
	}
	l, err := net.Listen("tcp", ":"+strconv.Itoa(*port))
	if err != nil {
		return err
	}
	fmt.Println("listening")
	ctx, cancel := context.WithTimeout(context.Background(), *ttl)
	defer cancel()
	return netcheck.ServeNonce(ctx, l, nonce)
}

// cmdRemoteCheck asks a RemoteProbe provider to connect to this server from
// outside. The provider's token comes from a file or the environment, never
// from an argument.
func cmdRemoteCheck(args []string) error {
	fs := flag.NewFlagSet("remote-check", flag.ContinueOnError)
	url := fs.String("url", os.Getenv("AUDITDSEC_PROBE_URL"), "RemoteProbe provider URL")
	tokenFile := fs.String("token-file", "", "file holding the provider token (or AUDITDSEC_PROBE_TOKEN)")
	ip := fs.String("ip", "", "this server's public address to test")
	port := fs.Int("port", 0, "port to test")
	family := fs.Int("family", 4, "4 or 6")
	kind := fs.String("kind", netcheck.KindTLS, "nonce | tls")
	serverName := fs.String("server-name", "", "name the certificate must be valid for (default: the address)")
	host := fs.String("host", "", "DNS name that must resolve to the address (optional)")
	cacert := fs.String("cacert", "", "CA file for the PROVIDER's certificate (default: system roots)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	token := os.Getenv("AUDITDSEC_PROBE_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("cannot read the provider token: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	if *url == "" || token == "" {
		fmt.Fprintln(os.Stderr, "external_check_unavailable: no RemoteProbe provider is configured (a URL and a token are needed)")
		kv("RESULT", "external_check_unavailable")
		return exitCode(exitUnavailable)
	}
	var roots *x509.CertPool
	if *cacert != "" {
		b, err := os.ReadFile(*cacert)
		if err != nil {
			return err
		}
		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM(b)
	}
	nonce := os.Getenv("AUDITDSEC_PROBE_NONCE")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	resp, err := netcheck.RemoteCheck(ctx, *url, token, netcheck.CheckRequest{
		IP: *ip, Port: *port, Family: *family, Host: *host, Kind: *kind, Nonce: nonce, ServerName: *serverName,
	}, roots)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		kv("RESULT", "external_check_unavailable")
		return exitCode(exitUnavailable)
	}
	kv("RESULT", resp.Result)
	if resp.Detail != "" {
		kv("DETAIL", resp.Detail)
	}
	if resp.TLS != nil {
		kv("TLS_VERIFIED", yesno(resp.TLS.Verified))
		if resp.TLS.Error != "" {
			kv("TLS_ERROR", resp.TLS.Error)
		}
		kv("TLS_NOT_AFTER", resp.TLS.NotAfter.Format(time.RFC3339))
		kv("TLS_SHA256", resp.TLS.SHA256)
	}
	if resp.Result != netcheck.ResultReachable {
		return exitCode(exitNotReach)
	}
	return nil
}
