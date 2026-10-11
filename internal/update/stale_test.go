package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// cdn answers like a cache that kept an old copy: a request with the cache
// bypass value gets the current files, any other gets the stale ones.
type cdn struct {
	mu                   sync.Mutex
	staleBody, staleSig  []byte
	freshBody, freshSig  []byte
	staleUntilBust       bool // false: always stale
	requests, bustedHits int
	headers              http.Header
}

func (c *cdn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests++
	c.headers = r.Header.Clone()
	busted := r.URL.Query().Get("cb") != ""
	if busted {
		c.bustedHits++
	}
	body, sig := c.staleBody, c.staleSig
	if busted && c.staleUntilBust {
		body, sig = c.freshBody, c.freshSig
	}
	if strings.HasSuffix(r.URL.Path, ".sig") {
		_, _ = w.Write(sig)
		return
	}
	_, _ = w.Write(body)
}

func newCDNRig(t *testing.T, c *cdn, mod func(*Options)) *Checker {
	t.Helper()
	srv := httptest.NewServer(c)
	t.Cleanup(srv.Close)
	clk := &clock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
	o := Options{Installed: inst(history(2), 1), Channel: ChannelMain, Arch: "amd64", Base: srv.URL + "/", Store: &memStore{}, Now: clk.now,
		Sleep: func(context.Context, time.Duration) {}, Rand: func() float64 { return 0.5 }, Client: &http.Client{Timeout: 2 * time.Second}}
	if mod != nil {
		mod(&o)
	}
	k, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// An older copy of a rolling file is asked for again with a changed address; the
// answer that comes is the current one and nothing was skipped.
func TestStaleCopyIsRetriedAndThenAccepted(t *testing.T) {
	old, cur := history(3), history(5)
	c := &cdn{staleBody: enc(t, old), freshBody: enc(t, cur), staleUntilBust: true}
	k := newCDNRig(t, c, func(o *Options) { o.Installed = inst(history(3), 1) })
	// The panel has already seen build 3.
	k.mu.Lock()
	r := Evaluate(k.opt.Installed, history(4), "amd64")
	k.st.Last, k.st.Commit = &r, k.opt.Installed.Commit
	k.mu.Unlock()

	got, err := k.Fetch(context.Background())
	if err != nil || got.Latest.Seq != 5 {
		t.Fatalf("Fetch = %+v, %v; want build 5", got, err)
	}
	if c.bustedHits == 0 {
		t.Error("the retry must change the address")
	}
	if c.headers.Get("Cache-Control") != "no-cache" {
		t.Errorf("Cache-Control = %q", c.headers.Get("Cache-Control"))
	}
}

func TestStaleCopyThatNeverClearsIsReportedAndKeepsTheLastGoodResult(t *testing.T) {
	cur, old := history(5), history(3)
	c := &cdn{staleBody: enc(t, old), freshBody: enc(t, old)}
	k := newCDNRig(t, c, func(o *Options) { o.Installed = inst(history(3), 1) })
	k.mu.Lock()
	r := Evaluate(k.opt.Installed, cur, "amd64")
	k.st.Last, k.st.Commit = &r, k.opt.Installed.Commit
	k.mu.Unlock()

	k.CheckNow(context.Background())
	v := k.View()
	if v.Result == nil || v.Result.Latest.Seq != 5 {
		t.Fatalf("an older copy must not replace what was seen: %+v", v)
	}
	if v.Error == "" || v.State == StateUpToDate {
		t.Errorf("the stale answer must be visible as a problem, not as 'up to date': %+v", v)
	}
	if c.requests != 3 {
		t.Errorf("three tries in all, got %d", c.requests)
	}
}

// The document and its signature can come from different moments; the signature
// check is never skipped, and a retry resolves a transient mismatch.
func TestDocumentSignatureMismatchIsRetried(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sign := func(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))) }
	old, cur := enc(t, history(3)), enc(t, history(4))
	// Fresh document with a stale signature at first; right after the bypass, both are current.
	c := &cdn{staleBody: cur, staleSig: sign(old), freshBody: cur, freshSig: sign(cur), staleUntilBust: true}
	k := newCDNRig(t, c, func(o *Options) { o.PublicKey = pub })
	got, err := k.Fetch(context.Background())
	if err != nil || got.Latest.Seq != 4 {
		t.Fatalf("Fetch = %+v, %v", got, err)
	}

	// And when it never clears, it fails closed.
	c2 := &cdn{staleBody: cur, staleSig: sign(old), freshBody: cur, freshSig: sign(old)}
	k2 := newCDNRig(t, c2, func(o *Options) { o.PublicKey = pub })
	if _, err := k2.Fetch(context.Background()); err == nil {
		t.Error("a document whose signature never matches must be refused")
	}
}

// A document that is itself invalid is not retried: waiting does not repair it.
func TestInvalidDocumentIsNotRetried(t *testing.T) {
	c := &cdn{staleBody: []byte("{not json"), freshBody: []byte("{not json")}
	k := newCDNRig(t, c, nil)
	if _, err := k.Fetch(context.Background()); err == nil {
		t.Fatal("an invalid document must fail")
	}
	if c.requests != 1 {
		t.Errorf("requests = %d, want 1", c.requests)
	}
}
