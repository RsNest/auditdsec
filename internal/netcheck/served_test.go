package netcheck

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The check reads what the port actually serves, and verifies it only against
// the roots it is given.
func TestCheckServedReadsThePresentedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	leaf := srv.Certificate()
	url := srv.URL // https://127.0.0.1:PORT; the test certificate names 127.0.0.1

	got, err := CheckServed(context.Background(), url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verified || got.Error == "" {
		t.Errorf("a test certificate verified against the system roots: %+v", got)
	}
	if !got.NotAfter.Equal(leaf.NotAfter) || got.Via != strings.TrimPrefix(url, "https://") {
		t.Errorf("not_after %v via %s", got.NotAfter, got.Via)
	}

	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	got, err = CheckServed(context.Background(), url, roots)
	if err != nil || !got.Verified {
		t.Errorf("against its own root: %+v %v", got, err)
	}

	if _, err := CheckServed(context.Background(), "http://example.com", nil); err == nil {
		t.Error("an http URL was accepted")
	}
	if _, err := CheckServed(context.Background(), "https://127.0.0.1:1", nil); err == nil {
		t.Error("a closed port gave a result")
	}
}

func TestCertProblem(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	short := func(left time.Duration) ServedCert { // a 6-day certificate
		end := now.Add(left)
		return ServedCert{Verified: true, NotBefore: end.Add(-144 * time.Hour), NotAfter: end}
	}
	long := func(left time.Duration) ServedCert { // a 90-day certificate
		end := now.Add(left)
		return ServedCert{Verified: true, NotBefore: end.Add(-90 * 24 * time.Hour), NotAfter: end}
	}
	cases := []struct {
		name  string
		c     ServedCert
		trust bool
		want  string // substring; "" means no problem
	}{
		{"fresh short", short(100 * time.Hour), true, ""},
		{"short, renewal overdue", short(30 * time.Hour), true, "expires in"},
		{"fresh long", long(60 * 24 * time.Hour), true, ""},
		{"long, renewal overdue", long(10 * 24 * time.Hour), true, "expires in"},
		{"expired", short(-time.Hour), false, "expired"},
		{"untrusted, trust checked", ServedCert{Error: "x509: unknown authority", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(80 * 24 * time.Hour)}, true, "does not verify"},
		{"untrusted, expiry only", ServedCert{Error: "x509: unknown authority", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(80 * 24 * time.Hour)}, false, ""},
	}
	for _, c := range cases {
		got := CertProblem(c.c, now, c.trust)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
