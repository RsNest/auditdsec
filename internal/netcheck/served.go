package netcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

// ServedCert is what the panel's public port presents right now. A file on
// disk proves nothing about that: a reload can fail and leave the old
// certificate in place until it expires.
type ServedCert struct {
	Verified  bool
	Error     string // why it did not verify; empty when it did
	NotBefore time.Time
	NotAfter  time.Time
	Via       string // the address actually dialled
}

// CheckServed connects to the host and port of an https:// URL and inspects
// the certificate. When the server cannot reach its own public address (some
// clouds do not loop it back), it tries the loopback address with the same
// server name, which still shows what the proxy serves.
func CheckServed(ctx context.Context, publicURL string, roots *x509.CertPool) (ServedCert, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return ServedCert{}, errors.New("not an https URL")
	}
	name, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	var last error
	for _, host := range []string{name, "127.0.0.1"} {
		addr := net.JoinHostPort(host, port)
		d := &net.Dialer{Timeout: 5 * time.Second}
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			last = err
			continue
		}
		conn := tls.Client(raw, &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		err = conn.HandshakeContext(ctx)
		if err != nil {
			raw.Close()
			last = err
			continue
		}
		st := conn.ConnectionState()
		conn.Close()
		info := verifyChain(st, name, roots)
		out := ServedCert{Verified: info.Verified, Error: info.Error, NotAfter: info.NotAfter, Via: addr}
		if len(st.PeerCertificates) > 0 {
			out.NotBefore = st.PeerCertificates[0].NotBefore
		}
		return out, nil
	}
	return ServedCert{}, fmt.Errorf("cannot reach the panel on %s or on loopback: %v", net.JoinHostPort(name, port), last)
}

// CertProblem judges a served certificate: empty when all is well. It warns
// once less than a quarter of the certificate's lifetime is left (and never
// later than a day before the end), which is after a healthy renewal should
// have happened for both 90-day and 6-day certificates.
func CertProblem(c ServedCert, now time.Time, checkTrust bool) string {
	left := c.NotAfter.Sub(now)
	switch {
	case !c.NotAfter.IsZero() && left <= 0:
		return fmt.Sprintf("expired at %s", c.NotAfter.UTC().Format(time.RFC3339))
	case checkTrust && !c.Verified:
		return "does not verify: " + c.Error
	}
	warnAt := c.NotAfter.Sub(c.NotBefore) / 4
	if warnAt < 24*time.Hour {
		warnAt = 24 * time.Hour
	}
	if !c.NotAfter.IsZero() && left < warnAt {
		return fmt.Sprintf("expires in %s (at %s); the renewal should have replaced it by now",
			left.Round(time.Minute), c.NotAfter.UTC().Format(time.RFC3339))
	}
	return ""
}
