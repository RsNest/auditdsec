package netcheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// RemoteProbe contract
//
// A machine that is NOT the server (otherwise "I can reach myself" proves
// nothing) is asked to connect to the server's public address and port and to
// say what happened. This file defines the request and answer, the client the
// installer uses, and the checker that cmd/auditdsec-probe serves. The owner
// runs the service on a separate host; no public instance is assumed to exist.

// Results.
const (
	ResultReachable     = "reachable"      // connected and got the expected answer
	ResultRefused       = "refused"        // the host answered with a reset: nothing listens there
	ResultTimeout       = "timeout"        // nothing came back: a firewall, NAT or routing, not told apart
	ResultWrongEndpoint = "wrong_endpoint" // connected, but something else answered
	ResultUnknown       = "unknown"        // the check itself could not be completed
)

// Kinds of check.
const (
	KindNonce = "nonce" // GET /.well-known/auditdsec-probe/<nonce> over plain HTTP
	KindTLS   = "tls"   // TLS handshake with verification, then GET /api/v1/setup/state
)

// NoncePath is where the temporary listener answers.
const NoncePath = "/.well-known/auditdsec-probe/"

type CheckRequest struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Family     int    `json:"family"` // 4 or 6
	Host       string `json:"host,omitempty"`
	Kind       string `json:"kind"`
	Nonce      string `json:"nonce,omitempty"`
	ServerName string `json:"server_name,omitempty"`
}

type TLSInfo struct {
	Verified bool      `json:"verified"`
	Error    string    `json:"error,omitempty"`
	NotAfter time.Time `json:"not_after,omitempty"`
	SHA256   string    `json:"sha256,omitempty"`
	Names    []string  `json:"names,omitempty"`
}

type CheckResponse struct {
	Result     string   `json:"result"`
	Detail     string   `json:"detail,omitempty"`
	HTTPStatus int      `json:"http_status,omitempty"`
	TLS        *TLSInfo `json:"tls,omitempty"`
}

// ---- the checker (server side) ----

// Checker performs one check. AllowPrivate exists for tests and for a lab on
// one machine; a public deployment must leave it off.
type Checker struct {
	AllowPrivate bool
	Roots        *x509.CertPool // nil: the system roots
	Timeout      time.Duration
	Resolver     interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
}

var errTarget = errors.New("target not allowed")

// Validate rejects anything that is not a plain public endpoint, before any
// connection is made.
func (c *Checker) Validate(ctx context.Context, r CheckRequest) (netip.Addr, error) {
	a, err := netip.ParseAddr(r.IP)
	if err != nil {
		return a, fmt.Errorf("%w: ip is not an address", errTarget)
	}
	a = a.Unmap()
	if r.Port < 1 || r.Port > 65535 {
		return a, fmt.Errorf("%w: port out of range", errTarget)
	}
	if (r.Family != 4 && r.Family != 6) || (r.Family == 4) != a.Is4() {
		return a, fmt.Errorf("%w: family does not match the address", errTarget)
	}
	if r.Kind != KindNonce && r.Kind != KindTLS {
		return a, fmt.Errorf("%w: unknown kind", errTarget)
	}
	if r.Kind == KindNonce && (len(r.Nonce) < 16 || len(r.Nonce) > 128 || !isToken(r.Nonce)) {
		return a, fmt.Errorf("%w: nonce must be 16-128 letters or digits", errTarget)
	}
	if !c.AllowPrivate && !IsPublic(a) {
		return a, fmt.Errorf("%w: %s is not a public address", errTarget, a)
	}
	if r.Host != "" {
		// Anti-rebinding: a host name is accepted only if it resolves to the
		// very address we were asked to test, and we then connect to the
		// literal address, never to the name.
		res := c.Resolver
		if res == nil {
			res = net.DefaultResolver
		}
		got, err := res.LookupNetIP(ctx, "ip", r.Host)
		if err != nil {
			return a, fmt.Errorf("%w: host does not resolve", errTarget)
		}
		found := false
		for _, g := range got {
			if g.Unmap() == a {
				found = true
			}
		}
		if !found {
			return a, fmt.Errorf("%w: host does not resolve to that address", errTarget)
		}
	}
	return a, nil
}

func isToken(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// Check runs one check.
func (c *Checker) Check(ctx context.Context, r CheckRequest) CheckResponse {
	a, err := c.Validate(ctx, r)
	if err != nil {
		return CheckResponse{Result: ResultUnknown, Detail: err.Error()}
	}
	to := c.Timeout
	if to == 0 {
		to = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	network := "tcp4"
	if r.Family == 6 {
		network = "tcp6"
	}
	endpoint := net.JoinHostPort(a.String(), strconv.Itoa(r.Port))
	dialer := &net.Dialer{Timeout: to, Control: func(_, address string, _ syscall.RawConn) error {
		// Checked again on the real connection: whatever happened before, a
		// private address is never connected to.
		h, _, _ := net.SplitHostPort(address)
		if ip, err := netip.ParseAddr(h); err == nil && !c.AllowPrivate && !IsPublic(ip.Unmap()) {
			return errTarget
		}
		return nil
	}}
	var info *TLSInfo
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, endpoint)
		},
	}
	scheme := "http"
	if r.Kind == KindTLS {
		scheme = "https"
		name := r.ServerName
		if name == "" {
			name = a.String()
		}
		tr.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			raw, err := dialer.DialContext(ctx, network, endpoint)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			if err := conn.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			info = verifyChain(conn.ConnectionState(), name, c.Roots)
			return conn, nil
		}
	}
	cl := &http.Client{Transport: tr, Timeout: to,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	path := NoncePath + r.Nonce
	if r.Kind == KindTLS {
		path = "/api/v1/setup/state"
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+endpoint+path, nil)
	if r.Kind == KindTLS && r.ServerName != "" {
		req.Host = r.ServerName
	}
	resp, err := cl.Do(req)
	if err != nil {
		return classify(err, info)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	out := CheckResponse{HTTPStatus: resp.StatusCode, TLS: info}
	switch {
	case r.Kind == KindNonce && resp.StatusCode == 200 && bytes.Contains(body, []byte(r.Nonce)):
		out.Result = ResultReachable
	case r.Kind == KindTLS && resp.StatusCode == 200 && bytes.Contains(body, []byte(`"state"`)):
		out.Result = ResultReachable
	default:
		out.Result = ResultWrongEndpoint
		out.Detail = fmt.Sprintf("connected, but the answer (HTTP %d) is not the expected one: another service listens there", resp.StatusCode)
	}
	return out
}

func verifyChain(st tls.ConnectionState, name string, roots *x509.CertPool) *TLSInfo {
	info := &TLSInfo{}
	if len(st.PeerCertificates) == 0 {
		info.Error = "no certificate"
		return info
	}
	leaf := st.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	info.SHA256, info.NotAfter = hex.EncodeToString(sum[:]), leaf.NotAfter.UTC()
	info.Names = append(info.Names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		info.Names = append(info.Names, ip.String())
	}
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: inter})
	if err != nil {
		info.Error = err.Error()
	} else {
		info.Verified = true
	}
	return info
}

func classify(err error, info *TLSInfo) CheckResponse {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return CheckResponse{Result: ResultRefused, Detail: "the connection was refused: nothing listens on that port, or a firewall rejects it with a reset"}
	case errors.Is(err, errTarget):
		return CheckResponse{Result: ResultUnknown, Detail: "target not allowed"}
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.As(err, &ne) && ne.Timeout():
		return CheckResponse{Result: ResultTimeout, Detail: "no answer in time: a local firewall, the provider's security group, NAT or routing may be dropping the connection; this cannot tell which"}
	}
	msg := err.Error()
	if strings.Contains(msg, "tls:") || strings.Contains(msg, "HTTP response to HTTPS") || strings.Contains(msg, "EOF") || strings.Contains(msg, "malformed HTTP") || strings.Contains(msg, "first record") {
		return CheckResponse{Result: ResultWrongEndpoint, Detail: "connected, but the peer did not speak the expected protocol: " + clip(msg), TLS: info}
	}
	return CheckResponse{Result: ResultUnknown, Detail: clip(msg)}
}

func clip(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// ---- the service (server side) ----

// Service is the HTTP front of a Checker: authentication, rate limits and a
// cap on concurrent checks, so it cannot be turned into a scanner.
type Service struct {
	Checker   *Checker
	Token     string
	PerMinute int // all callers together
	PerTarget int // per target address per minute
	MaxActive int
	Now       func() time.Time

	mu     sync.Mutex
	window []time.Time
	target map[string][]time.Time
	active int
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) allow(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.now().Add(-time.Minute)
	prune := func(in []time.Time) []time.Time {
		i := 0
		for i < len(in) && in[i].Before(cut) {
			i++
		}
		return in[i:]
	}
	if s.target == nil {
		s.target = map[string][]time.Time{}
	}
	s.window = prune(s.window)
	t := prune(s.target[ip])
	lim, per := s.PerMinute, s.PerTarget
	if lim <= 0 {
		lim = 30
	}
	if per <= 0 {
		per = 6
	}
	if len(s.window) >= lim || len(t) >= per || len(s.target) > 4096 {
		s.target[ip] = t
		return false
	}
	s.window = append(s.window, s.now())
	s.target[ip] = append(t, s.now())
	return true
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("POST /v1/check", func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.Token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		var req CheckRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		if !s.allow(req.IP) {
			w.Header().Set("Retry-After", "30")
			http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
			return
		}
		s.mu.Lock()
		max := s.MaxActive
		if max <= 0 {
			max = 4
		}
		busy := s.active >= max
		if !busy {
			s.active++
		}
		s.mu.Unlock()
		if busy {
			http.Error(w, `{"error":"busy"}`, http.StatusServiceUnavailable)
			return
		}
		defer func() { s.mu.Lock(); s.active--; s.mu.Unlock() }()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Checker.Check(r.Context(), req))
	})
	return mux
}

// ---- the client (installer side) ----

// ErrUnavailable means the provider could not be used at all. It is not a
// verdict about the port: the installer reports it as external_check_unavailable.
var ErrUnavailable = errors.New("external_check_unavailable")

// RemoteCheck asks a RemoteProbe provider to test an endpoint. The token is
// only ever sent over HTTPS, or to a loopback address (a lab).
func RemoteCheck(ctx context.Context, base, token string, req CheckRequest, roots *x509.CertPool) (CheckResponse, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" {
		return CheckResponse{}, fmt.Errorf("%w: the provider URL is not valid", ErrUnavailable)
	}
	loop := false
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		loop = ip.IsLoopback()
	} else if u.Hostname() == "localhost" {
		loop = true
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loop) {
		return CheckResponse{}, fmt.Errorf("%w: the provider URL must be https (the token is secret)", ErrUnavailable)
	}
	body, _ := json.Marshal(req)
	hr, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String()+"/v1/check", bytes.NewReader(body))
	hr.Header.Set("Authorization", "Bearer "+token)
	hr.Header.Set("Content-Type", "application/json")
	cl := &http.Client{Timeout: 40 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(hr)
	if err != nil {
		return CheckResponse{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return CheckResponse{}, fmt.Errorf("%w: the provider answered HTTP %d", ErrUnavailable, resp.StatusCode)
	}
	var out CheckResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&out); err != nil {
		return CheckResponse{}, fmt.Errorf("%w: unreadable answer", ErrUnavailable)
	}
	return out, nil
}

// ---- the temporary listener ----

// ServeNonce answers the nonce path on a listener until ctx ends. It serves
// nothing else, so for the few seconds it exists the port exposes one fixed
// string and no panel API.
func ServeNonce(ctx context.Context, l net.Listener, nonce string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+NoncePath+nonce, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, "auditdsec-probe "+nonce+"\n")
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = srv.Shutdown(sc)
	}()
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
