package netcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type fakeResolver struct {
	name   string
	v4, v6 []string
	cname  string
	fail   bool
}

func (f fakeResolver) Name() string { return f.name }
func (f fakeResolver) LookupIP(_ context.Context, network, _ string) ([]netip.Addr, error) {
	if f.fail {
		return nil, errors.New("timeout")
	}
	src := f.v4
	if network == "ip6" {
		src = f.v6
	}
	var out []netip.Addr
	for _, s := range src {
		out = append(out, netip.MustParseAddr(s))
	}
	if len(out) == 0 {
		return nil, &net.DNSError{IsNotFound: true}
	}
	return out, nil
}
func (f fakeResolver) LookupCNAME(context.Context, string) (string, error) {
	if f.cname == "" {
		return "panel.example.com.", nil
	}
	return f.cname, nil
}

func ad(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestNormalizeHost(t *testing.T) {
	good := map[string]string{"Panel.Example.com": "panel.example.com", "panel.example.com.": "panel.example.com", " a-b.example.org ": "a-b.example.org"}
	for in, want := range good {
		if got, err := NormalizeHost(in); err != nil || got != want {
			t.Errorf("%q = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "https://x.example.com", "x.example.com/path", "x.example.com:8443", "localhost", "a b.example.com",
		"x.example.com;rm -rf", "$(id).example.com", "-x.example.com", "x..example.com", "пример.рф"} {
		if got, err := NormalizeHost(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestJudgeDomain(t *testing.T) {
	srv := Server{Global: []netip.Addr{ad("198.51.100.7")}} // pretend-public for the test
	rs := func(v4, v6 []string) []Resolver {
		return []Resolver{fakeResolver{name: "a", v4: v4, v6: v6}, fakeResolver{name: "b", v4: v4, v6: v6}}
	}
	cases := []struct {
		name     string
		v4, v6   []string
		srv      Server
		ok       bool
		contains string
	}{
		{"matches", []string{"198.51.100.7"}, nil, srv, true, ""},
		{"a foreign A beside the right one", []string{"198.51.100.7", "203.0.113.9"}, nil, srv, false, "203.0.113.9"},
		{"AAAA that is not ours", []string{"198.51.100.7"}, []string{"2001:db8::1"}, srv, false, "AAAA"},
		{"no records", nil, nil, srv, false, "no A or AAAA"},
		{"server unknown", []string{"198.51.100.7"}, nil, Server{}, false, "--public-ip"},
		{"stated address", []string{"203.0.113.9"}, nil, Server{Claimed: []netip.Addr{ad("203.0.113.9")}}, true, ""},
		{"egress hint counts as a hint", []string{"203.0.113.9"}, nil, Server{Egress: []netip.Addr{ad("203.0.113.9")}}, true, ""},
	}
	for _, c := range cases {
		res := LookupAll(context.Background(), "panel.example.com", rs(c.v4, c.v6), 1, 0)
		v := JudgeDomain(res, c.srv)
		if v.OK != c.ok || (c.contains != "" && !strings.Contains(strings.Join(v.Problems, "\n"), c.contains)) {
			t.Errorf("%s: ok=%v problems=%v", c.name, v.OK, v.Problems)
		}
	}
	// Resolvers that disagree are a stop, not a guess.
	res := LookupAll(context.Background(), "panel.example.com", []Resolver{
		fakeResolver{name: "a", v4: []string{"198.51.100.7"}}, fakeResolver{name: "b", v4: []string{"203.0.113.9"}}}, 1, 0)
	if v := JudgeDomain(res, srv); v.OK || !strings.Contains(strings.Join(v.Problems, " "), "disagree") {
		t.Errorf("disagreement: %+v", v)
	}
	// All resolvers failing is not "no records".
	res = LookupAll(context.Background(), "x.example.com", []Resolver{fakeResolver{name: "a", fail: true}}, 1, 0)
	if v := JudgeDomain(res, srv); v.OK || !strings.Contains(v.Problems[0], "none of the public DNS servers answered") {
		t.Errorf("all failing: %+v", v)
	}
}

func TestIsPublic(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !IsPublic(ad(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "::1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
		"224.0.0.1", "fe80::1", "fc00::1", "::ffff:10.0.0.1", "203.0.113.10", "2001:db8::10", "fd00::1"} {
		if IsPublic(ad(s)) {
			t.Errorf("%s should not be public", s)
		}
	}
}

func TestBindAndCandidates(t *testing.T) {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip("cannot listen")
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	rs := Bind(port)
	if Usable(rs) || !strings.Contains(DescribeBind(port, rs), "already in use") {
		t.Errorf("a busy port reported usable: %+v", rs)
	}
	l.Close()
	if !Usable(Bind(port)) {
		t.Error("a freed port is not usable")
	}
	c := Candidates(443, 16, 20000, 29999, map[int]bool{9477: true, 2019: true, 20000: true}, rand.New(rand.NewSource(1)))
	if c[0] != 443 || len(c) != 17 {
		t.Fatalf("candidates = %v", c)
	}
	seen := map[int]bool{}
	elo, ehi := EphemeralRange()
	for _, p := range c {
		if seen[p] {
			t.Errorf("duplicate %d", p)
		}
		seen[p] = true
		if p != 443 && (p == 20000 || p < 20000 || p > 29999 || (p >= elo && p <= ehi)) {
			t.Errorf("bad candidate %d", p)
		}
	}
}

func testChecker() *Checker { return &Checker{AllowPrivate: true, Timeout: 3 * time.Second} }

func TestValidateRefusesDangerousTargets(t *testing.T) {
	c := &Checker{Timeout: time.Second} // as deployed: AllowPrivate off
	bad := []CheckRequest{
		{IP: "127.0.0.1", Port: 443, Family: 4, Kind: KindTLS},
		{IP: "10.1.2.3", Port: 443, Family: 4, Kind: KindTLS},
		{IP: "169.254.169.254", Port: 80, Family: 4, Kind: KindNonce, Nonce: strings.Repeat("a", 20)},
		{IP: "::1", Port: 443, Family: 6, Kind: KindTLS},
		{IP: "8.8.8.8", Port: 0, Family: 4, Kind: KindTLS},
		{IP: "8.8.8.8", Port: 70000, Family: 4, Kind: KindTLS},
		{IP: "8.8.8.8", Port: 443, Family: 6, Kind: KindTLS},
		{IP: "8.8.8.8", Port: 443, Family: 4, Kind: "proxy"},
		{IP: "8.8.8.8", Port: 80, Family: 4, Kind: KindNonce, Nonce: "short"},
		{IP: "not-an-ip", Port: 443, Family: 4, Kind: KindTLS},
	}
	for _, r := range bad {
		if resp := c.Check(context.Background(), r); resp.Result != ResultUnknown {
			t.Errorf("%+v was not refused: %+v", r, resp)
		}
	}
	// A host name that resolves elsewhere is refused (rebinding).
	c.Resolver = rebind{}
	r := CheckRequest{IP: "8.8.8.8", Port: 443, Family: 4, Kind: KindTLS, Host: "evil.example.com"}
	if resp := c.Check(context.Background(), r); !strings.Contains(resp.Detail, "does not resolve to that address") {
		t.Errorf("rebinding: %+v", resp)
	}
}

type rebind struct{}

func (rebind) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{ad("10.0.0.5")}, nil
}

func TestCheckNonceOutcomes(t *testing.T) {
	nonce := strings.Repeat("Ab3", 8)
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ServeNonce(ctx, l, nonce)
	port := l.Addr().(*net.TCPAddr).Port
	req := CheckRequest{IP: "127.0.0.1", Port: port, Family: 4, Kind: KindNonce, Nonce: nonce}
	if r := testChecker().Check(ctx, req); r.Result != ResultReachable {
		t.Errorf("nonce listener: %+v", r)
	}
	req.Nonce = strings.Repeat("Zz9", 8)
	if r := testChecker().Check(ctx, req); r.Result != ResultWrongEndpoint {
		t.Errorf("another nonce: %+v", r)
	}
	// Something else on the port: wrong endpoint.
	other := httptest.NewServer(http.NotFoundHandler())
	defer other.Close()
	op := other.Listener.Addr().(*net.TCPAddr).Port
	if r := testChecker().Check(ctx, CheckRequest{IP: "127.0.0.1", Port: op, Family: 4, Kind: KindNonce, Nonce: nonce}); r.Result != ResultWrongEndpoint {
		t.Errorf("foreign service: %+v", r)
	}
	// Nothing listening: refused.
	free, _ := net.Listen("tcp4", "127.0.0.1:0")
	fp := free.Addr().(*net.TCPAddr).Port
	free.Close()
	if r := testChecker().Check(ctx, CheckRequest{IP: "127.0.0.1", Port: fp, Family: 4, Kind: KindNonce, Nonce: nonce}); r.Result != ResultRefused {
		t.Errorf("closed port: %+v", r)
	}
}

func TestCheckTLSVerification(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/setup/state" {
			w.Write([]byte(`{"state":"ready"}`))
			return
		}
		http.NotFound(w, r)
	}))
	ts.StartTLS()
	defer ts.Close()
	port := ts.Listener.Addr().(*net.TCPAddr).Port
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	c := testChecker()
	c.Roots = pool
	// httptest's certificate is for example.com and 127.0.0.1.
	r := c.Check(context.Background(), CheckRequest{IP: "127.0.0.1", Port: port, Family: 4, Kind: KindTLS, ServerName: "example.com"})
	if r.Result != ResultReachable || r.TLS == nil || !r.TLS.Verified || r.TLS.SHA256 == "" {
		t.Errorf("trusted certificate: %+v %+v", r, r.TLS)
	}
	// The same certificate against a CA that does not know it: reachable, but not verified.
	c.Roots = x509.NewCertPool()
	r = c.Check(context.Background(), CheckRequest{IP: "127.0.0.1", Port: port, Family: 4, Kind: KindTLS, ServerName: "example.com"})
	if r.Result != ResultReachable || r.TLS == nil || r.TLS.Verified || r.TLS.Error == "" {
		t.Errorf("untrusted certificate: %+v %+v", r, r.TLS)
	}
	// The wrong name.
	c.Roots = pool
	r = c.Check(context.Background(), CheckRequest{IP: "127.0.0.1", Port: port, Family: 4, Kind: KindTLS, ServerName: "other.example.org"})
	if r.TLS == nil || r.TLS.Verified {
		t.Errorf("wrong name verified: %+v", r.TLS)
	}
	// Plain HTTP where TLS is expected.
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	r = c.Check(context.Background(), CheckRequest{IP: "127.0.0.1", Port: plain.Listener.Addr().(*net.TCPAddr).Port, Family: 4, Kind: KindTLS, ServerName: "example.com"})
	if r.Result != ResultWrongEndpoint {
		t.Errorf("plain HTTP on a TLS check: %+v", r)
	}
	_ = tls.VersionTLS12
}

func TestServiceAuthRateAndClient(t *testing.T) {
	svc := &Service{Checker: testChecker(), Token: "secret-token", PerTarget: 2}
	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()
	free, _ := net.Listen("tcp4", "127.0.0.1:0")
	fp := free.Addr().(*net.TCPAddr).Port
	free.Close()
	req := CheckRequest{IP: "127.0.0.1", Port: fp, Family: 4, Kind: KindNonce, Nonce: strings.Repeat("a", 20)}

	if _, err := RemoteCheck(context.Background(), srv.URL, "wrong", req, nil); !errors.Is(err, ErrUnavailable) {
		t.Errorf("wrong token: %v", err)
	}
	r, err := RemoteCheck(context.Background(), srv.URL, "secret-token", req, nil)
	if err != nil || r.Result != ResultRefused {
		t.Fatalf("%+v %v", r, err)
	}
	RemoteCheck(context.Background(), srv.URL, "secret-token", req, nil)
	if _, err := RemoteCheck(context.Background(), srv.URL, "secret-token", req, nil); !errors.Is(err, ErrUnavailable) {
		t.Errorf("the per-target limit did not stop the third check: %v", err)
	}
	// The token is never sent in clear to a non-loopback provider.
	if _, err := RemoteCheck(context.Background(), "http://probe.example.net:8080", "secret-token", req, nil); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "https") {
		t.Errorf("plain http provider accepted: %v", err)
	}
	b, _ := json.Marshal(req)
	hr, _ := http.NewRequest("POST", srv.URL+"/v1/check", strings.NewReader(string(b)))
	if resp, _ := http.DefaultClient.Do(hr); resp.StatusCode != 401 {
		t.Errorf("no token = %d", resp.StatusCode)
	}
}
