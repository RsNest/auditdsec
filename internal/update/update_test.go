package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func sha(n int) string { return fmt.Sprintf("%040x", n) }

func entry(id string, mods ...func(*Entry)) Entry {
	e := Entry{
		ID: "2026-10-" + id, Date: "2026-10-01",
		Title:    Text{EN: "Title " + id, RU: "Заголовок " + id},
		Added:    Lists{EN: []string{"Added " + id}, RU: []string{"Добавлено " + id}},
		Requires: Requires{Migration: "none"},
	}
	for _, m := range mods {
		m(&e)
	}
	return e
}

func images(platforms ...string) map[string]ImageRef {
	if len(platforms) == 0 {
		platforms = []string{"linux/amd64", "linux/arm64"}
	}
	return map[string]ImageRef{"auditdsec": {Ref: "ghcr.io/rsnest/auditdsec:sha-x", Digest: "sha256:" + strings.Repeat("a", 64), Platforms: platforms}}
}

// history builds n publications, newest first. Commit IDs are deliberately NOT
// in publication order, so any comparison of them would give the wrong answer.
func history(n int) Metadata {
	m := Metadata{Schema: 1, Channel: ChannelMain, Repo: "RsNest/auditdsec", GeneratedAt: "2026-10-11T00:00:00Z"}
	for i := n; i >= 1; i-- {
		b := Build{Seq: i, Version: fmt.Sprintf("0.3.0-dev+%012x", 0xfff-i), Commit: sha(0xfff - i*7),
			Published: time.Date(2026, 10, i, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
			Entries:   []Entry{entry(fmt.Sprintf("%02d-change-%d", i, i))}}
		if i == n {
			b.Images = images()
		}
		m.Builds = append(m.Builds, b)
	}
	return m
}

func enc(t *testing.T, m Metadata) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseRejectsBadDocuments(t *testing.T) {
	good := history(3)
	if _, err := Parse(enc(t, good)); err != nil {
		t.Fatal(err)
	}
	mut := map[string]func(*Metadata){
		"schema":    func(m *Metadata) { m.Schema = 2 },
		"channel":   func(m *Metadata) { m.Channel = "beta" },
		"no builds": func(m *Metadata) { m.Builds = nil },
		"order":     func(m *Metadata) { m.Builds[0].Seq, m.Builds[1].Seq = m.Builds[1].Seq, m.Builds[0].Seq },
		"commit":    func(m *Metadata) { m.Builds[1].Commit = "main" },
		"time":      func(m *Metadata) { m.Builds[1].Published = "yesterday" },
		"digest": func(m *Metadata) {
			img := m.Builds[0].Images["auditdsec"]
			img.Digest = "sha256:abc"
			m.Builds[0].Images["auditdsec"] = img
		},
		"foreign registry": func(m *Metadata) {
			img := m.Builds[0].Images["auditdsec"]
			img.Ref = "evil.example/x:1"
			m.Builds[0].Images["auditdsec"] = img
		},
		"no agent image": func(m *Metadata) { m.Builds[0].Images = nil },
		"platform": func(m *Metadata) {
			img := m.Builds[0].Images["auditdsec"]
			img.Platforms = []string{"windows/amd64"}
			m.Builds[0].Images["auditdsec"] = img
		},
		"repeated entry": func(m *Metadata) { m.Builds[1].Entries = m.Builds[0].Entries },
		"entry id":       func(m *Metadata) { m.Builds[0].Entries[0].ID = "../../etc" },
		"long note":      func(m *Metadata) { m.Builds[0].Entries[0].Added.EN = []string{strings.Repeat("x", 700)} },
		"migration kind": func(m *Metadata) { m.Builds[0].Entries[0].Requires.Migration = "yolo" },
	}
	for name, f := range mut {
		m := history(3)
		f(&m)
		if _, err := Parse(enc(t, m)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := Parse([]byte("not json")); err == nil {
		t.Error("garbage was accepted")
	}
	if _, err := Parse(make([]byte, MaxDocument+1)); err == nil {
		t.Error("an oversized document was accepted")
	}
}

func TestSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	doc := []byte(`{"x":1}`)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, doc))
	if err := Verify(doc, []byte(sig), pub); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ doc, sig string }{
		"changed document": {`{"x":2}`, sig}, "empty": {string(doc), ""}, "garbage": {string(doc), "!!!"},
		"wrong key": {string(doc), base64.StdEncoding.EncodeToString(ed25519.Sign(func() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(rand.Reader); return k }(), doc))},
	} {
		if err := Verify([]byte(c.doc), []byte(c.sig), pub); err == nil {
			t.Errorf("%s verified", name)
		}
	}
	if _, err := ParsePublicKey("AAAA"); err == nil {
		t.Error("a short key was accepted")
	}
}

func inst(m Metadata, back int) Installed {
	b := m.Builds[back]
	return Installed{Version: b.Version, Commit: b.Commit, Date: b.Published}
}

func TestMainChannelFollowsPublicationOrder(t *testing.T) {
	m := history(6)
	if r := Evaluate(inst(m, 0), m, "amd64"); r.State != StateUpToDate || len(r.Entries) != 0 {
		t.Errorf("latest: %+v", r)
	}
	// Three builds behind: the notes of every skipped build, newest first,
	// although the installed commit sorts HIGHER than the latest as a string.
	cur := inst(m, 3)
	if !(cur.Commit > m.Latest().Commit) {
		t.Fatal("the fixture must make string order disagree with publication order")
	}
	r := Evaluate(cur, m, "amd64")
	if r.State != StateAvailable || len(r.Entries) != 3 || r.Truncated {
		t.Fatalf("%+v", r)
	}
	if r.Entries[0].ID != m.Builds[0].Entries[0].ID || r.Entries[2].ID != m.Builds[2].Entries[0].ID {
		t.Errorf("notes must run from the latest back to just after the installed build: %v", r.Entries)
	}
}

func TestSkippedBreakingChangesAndRequirementsAreKept(t *testing.T) {
	m := history(5)
	m.Builds[3].Entries[0].Breaking = []Text{{EN: "The config key a was renamed", RU: "Ключ a переименован"}}
	m.Builds[3].Entries[0].Requires = Requires{InstallerUpdate: true, Migration: "irreversible"}
	m.Builds[1].Entries[0].Requires = Requires{Migration: "reversible"}
	r := Evaluate(inst(m, 4), m, "amd64") // installed before the incompatible change; latest is two later
	if len(r.Breaking) != 1 || !r.Requires.InstallerUpdate || r.Requires.Migration != "irreversible" {
		t.Errorf("an intermediate incompatible change must reach the reader: %+v", r)
	}
	// Someone already past it is not warned about it.
	if r := Evaluate(inst(m, 2), m, "amd64"); len(r.Breaking) != 0 || r.Requires.Migration != "reversible" {
		t.Errorf("%+v", r)
	}
}

func TestInstalledBuildNotInTheHistory(t *testing.T) {
	m := history(4)
	// A build older than the whole history is behind, and says the list is cut.
	old := Installed{Version: "0.2.0", Commit: sha(1), Date: "2026-01-01T00:00:00Z"}
	r := Evaluate(old, m, "amd64")
	if r.State != StateAvailable || !r.Truncated || len(r.Entries) != 4 {
		t.Errorf("%+v", r)
	}
	// An unknown build that is not provably older is never declared current
	// or behind, and no list of changes is presented as its own.
	for _, i := range []Installed{
		{Version: "0.3.0-dev+local", Commit: sha(2), Date: "2026-12-01T00:00:00Z"},
		{Version: "dev", Commit: "none"},
		{Version: "dev", Commit: ""},
	} {
		r := Evaluate(i, m, "amd64")
		if r.State != StateUnknownInstalled || len(r.Entries) != 0 {
			t.Errorf("%+v: %+v", i, r)
		}
	}
}

func TestArchitectureAndIncompletePublication(t *testing.T) {
	m := history(2)
	m.Builds[0].Images = images("linux/amd64")
	if r := Evaluate(inst(m, 1), m, "arm64"); r.State != StateUnsupportedArch {
		t.Errorf("an unsupported architecture must not be offered the update: %+v", r)
	}
	if r := Evaluate(inst(m, 1), m, "amd64"); r.State != StateAvailable {
		t.Errorf("%+v", r)
	}
	m.Builds[0].Images = nil
	if r := Evaluate(inst(m, 1), m, "amd64"); r.State != StateIncomplete {
		t.Errorf("a publication without an image is not an update: %+v", r)
	}
}

func TestStableChannelUsesVersions(t *testing.T) {
	mk := func(vs ...string) Metadata {
		m := Metadata{Schema: 1, Channel: ChannelStable, Repo: "RsNest/auditdsec"}
		for i, v := range vs {
			b := Build{Seq: len(vs) - i, Version: v, Commit: sha(100 + len(vs) - i), Published: "2026-10-01T00:00:00Z",
				Entries: []Entry{entry(fmt.Sprintf("%02d-release-%d", 10+len(vs)-i, len(vs)-i))}}
			if i == 0 {
				b.Images = images()
			}
			m.Builds = append(m.Builds, b)
		}
		return m
	}
	m := mk("0.3.10", "0.3.9", "0.3.2", "0.3.0")
	cases := []struct {
		installed string
		state     string
		entries   int
	}{
		{"0.3.10", StateUpToDate, 0}, {"0.3.9", StateAvailable, 1}, {"0.3.0", StateAvailable, 3},
		{"0.3.1", StateAvailable, 3},      // between releases: the notes of the ones after it
		{"0.4.0", StateUpToDate, 0},       // newer than the latest release
		{"0.3.10-rc1", StateAvailable, 0}, // a pre-release is behind its release
		{"garbage", StateUnknownInstalled, 0},
	}
	for _, c := range cases {
		r := Evaluate(Installed{Version: c.installed, Commit: sha(5)}, m, "amd64")
		if r.State != c.state || (c.state == StateAvailable && c.entries > 0 && len(r.Entries) != c.entries) {
			t.Errorf("%s: %+v", c.installed, r)
		}
	}
	if DefaultChannel("0.3.1") != ChannelStable || DefaultChannel("0.3.0-dev+abcdef123456") != ChannelMain || DefaultChannel("dev") != ChannelMain {
		t.Error("channel choice")
	}
}

// ---- the checker --------------------------------------------------------

type source struct {
	mu       sync.Mutex
	body     []byte
	sig      []byte
	status   int
	requests []*http.Request
	delay    time.Duration
}

func (s *source) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Clone(context.Background()))
	body, sig, status, delay := s.body, s.sig, s.status, s.delay
	s.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if strings.HasSuffix(r.URL.Path, ".sig") {
		_, _ = w.Write(sig)
		return
	}
	_, _ = w.Write(body)
}

type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memStore) GetMeta(k string) string { s.mu.Lock(); defer s.mu.Unlock(); return s.m[k] }
func (s *memStore) SetMeta(k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
	return nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func rig(t *testing.T, src *source, mod func(*Options)) (*Checker, *clock, *memStore) {
	t.Helper()
	srv := httptest.NewServer(src)
	t.Cleanup(srv.Close)
	clk := &clock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
	st := &memStore{}
	o := Options{Installed: Installed{Version: "x"}, Channel: ChannelMain, Arch: "amd64", Base: srv.URL + "/", Store: st, Now: clk.now,
		Sleep: func(context.Context, time.Duration) {},
		Rand:  func() float64 { return 0.5 }, Client: &http.Client{Timeout: 2 * time.Second}}
	if mod != nil {
		mod(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c, clk, st
}

func TestCheckerReportsAvailableAndRemembersIt(t *testing.T) {
	m := history(4)
	src := &source{body: enc(t, m)}
	c, clk, st := rig(t, src, func(o *Options) { o.Installed = inst(m, 2) })
	if v := c.View(); v.State != "never" {
		t.Errorf("before any check the state must be 'never', got %q", v.State)
	}
	c.CheckNow(context.Background())
	v := c.View()
	if v.State != StateAvailable || len(v.Result.Entries) != 2 || v.LastSuccess.IsZero() || v.Error != "" {
		t.Fatalf("%+v", v)
	}
	// After a restart the answer is there at once, without the network.
	again, err := New(Options{Installed: inst(m, 2), Channel: ChannelMain, Arch: "amd64", Base: "http://127.0.0.1:1/", Store: st, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	if v := again.View(); v.State != StateAvailable || v.LastSuccess.IsZero() {
		t.Errorf("restart: %+v", v)
	}
	// After the update was applied that answer is about another build: forgotten.
	upd, _ := New(Options{Installed: inst(m, 0), Channel: ChannelMain, Arch: "amd64", Base: "http://127.0.0.1:1/", Store: st, Now: clk.now})
	if v := upd.View(); v.Result != nil || v.State == StateAvailable {
		t.Errorf("a result computed for the old build must not survive an update: %+v", v)
	}
}

// A failed check is never shown as "up to date", and the last success is kept.
func TestFailureIsNeverUpToDate(t *testing.T) {
	m := history(3)
	src := &source{body: enc(t, m)}
	c, clk, _ := rig(t, src, func(o *Options) { o.Installed = inst(m, 0) })
	c.CheckNow(context.Background())
	if v := c.View(); v.State != StateUpToDate {
		t.Fatalf("%+v", v)
	}
	ok := c.View().LastSuccess
	for name, f := range map[string]func(){
		"server error": func() { src.mu.Lock(); src.status = 500; src.mu.Unlock() },
		"not found":    func() { src.mu.Lock(); src.status = 404; src.mu.Unlock() },
		"garbage":      func() { src.mu.Lock(); src.status, src.body = 0, []byte("<html>"); src.mu.Unlock() },
	} {
		f()
		clk.t = clk.t.Add(time.Hour)
		c.CheckNow(context.Background())
		v := c.View()
		if v.State != "unavailable" || v.Error == "" || !v.LastSuccess.Equal(ok) {
			t.Errorf("%s: %+v", name, v)
		}
		if strings.Contains(v.Error, "127.0.0.1") {
			t.Errorf("%s: the error shows the address: %q", name, v.Error)
		}
	}
}

func TestBackoffGrowsAndResets(t *testing.T) {
	src := &source{status: 503}
	c, clk, _ := rig(t, src, nil)
	var waits []time.Duration
	for i := 0; i < 6; i++ {
		c.CheckNow(context.Background())
		c.mu.Lock()
		waits = append(waits, c.next.Sub(clk.t))
		c.mu.Unlock()
	}
	want := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 6 * time.Hour}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("wait %d = %v want %v (all: %v)", i, waits[i], want[i], waits)
		}
	}
	m := history(2)
	src.mu.Lock()
	src.status, src.body = 0, enc(t, m)
	src.mu.Unlock()
	c.CheckNow(context.Background())
	c.mu.Lock()
	normal := c.next.Sub(clk.t)
	c.mu.Unlock()
	if normal != 6*time.Hour { // Rand()=0.5 is the middle of the jitter
		t.Errorf("after success the normal interval returns: %v", normal)
	}
}

func TestJitterStaysWithinBounds(t *testing.T) {
	src := &source{body: enc(t, history(2))}
	for _, r := range []float64{0, 0.999999} {
		r := r
		c, clk, _ := rig(t, src, func(o *Options) { o.Rand = func() float64 { return r } })
		c.CheckNow(context.Background())
		c.mu.Lock()
		d := c.next.Sub(clk.t)
		c.mu.Unlock()
		if d < 6*time.Hour-30*time.Minute || d > 6*time.Hour+30*time.Minute {
			t.Errorf("rand %v: %v", r, d)
		}
	}
}

func TestManualCheckIsRateLimited(t *testing.T) {
	src := &source{body: enc(t, history(2))}
	c, clk, _ := rig(t, src, nil)
	if err := c.Request(); err != nil {
		t.Fatal(err)
	}
	c.CheckNow(context.Background())
	if err := c.Request(); err != ErrTooSoon {
		t.Errorf("a second press right after a check: %v", err)
	}
	clk.t = clk.t.Add(2 * time.Minute)
	if err := c.Request(); err != nil {
		t.Errorf("after the gap: %v", err)
	}
}

func TestSignatureIsRequiredWhenAKeyIsBuiltIn(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := history(3)
	doc := enc(t, m)
	good := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, doc)))
	src := &source{body: doc, sig: good}
	c, _, _ := rig(t, src, func(o *Options) { o.PublicKey = pub; o.Installed = inst(m, 1) })
	c.CheckNow(context.Background())
	if v := c.View(); v.State != StateAvailable {
		t.Fatalf("a signed document: %+v", v)
	}
	// Tampered content, a missing signature and a signature of other content all fail closed.
	for name, mut := range map[string]func(){
		"tampered": func() { src.mu.Lock(); src.body = append([]byte(" "), doc...); src.mu.Unlock() },
		"unsigned": func() { src.mu.Lock(); src.body, src.sig = doc, nil; src.mu.Unlock() },
	} {
		mut()
		c2, _, _ := rig(t, src, func(o *Options) { o.PublicKey = pub; o.Installed = inst(m, 1) })
		c2.CheckNow(context.Background())
		if v := c2.View(); v.State != "unavailable" || v.Result != nil {
			t.Errorf("%s: %+v", name, v)
		}
	}
}

func TestRequestCarriesNothingAboutTheServer(t *testing.T) {
	src := &source{body: enc(t, history(2))}
	c, _, _ := rig(t, src, func(o *Options) { o.Installed = Installed{Version: "0.3.0-dev+secretbuild", Commit: sha(9)} })
	c.CheckNow(context.Background())
	src.mu.Lock()
	defer src.mu.Unlock()
	if len(src.requests) != 1 {
		t.Fatalf("%d requests", len(src.requests))
	}
	r := src.requests[0]
	if r.URL.RawQuery != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("User-Agent") != "auditdsec-update-check" {
		t.Errorf("%v %v", r.URL, r.Header)
	}
	dump := fmt.Sprint(r.Header, r.URL)
	if strings.Contains(dump, "secretbuild") || strings.Contains(dump, sha(9)) {
		t.Errorf("the installed version leaked into the request: %s", dump)
	}
}

func TestSourceRules(t *testing.T) {
	for _, base := range []string{"http://example.com/", "ftp://x/", "file:///etc/", "not a url", "https://"} {
		if _, err := New(Options{Installed: Installed{Version: "x"}, Channel: ChannelMain, Base: base}); err == nil {
			t.Errorf("%q was accepted", base)
		}
	}
	// A redirect off the allowed hosts is refused.
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{}")) }))
	defer evil.Close()
	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, evil.URL, http.StatusFound) }))
	defer hop.Close()
	c, err := New(Options{Installed: Installed{Version: "x"}, Channel: ChannelMain, Base: hop.URL + "/", Store: &memStore{}})
	if err != nil {
		t.Fatal(err)
	}
	c.CheckNow(context.Background())
	if v := c.View(); v.State != "unavailable" {
		t.Errorf("a redirect to an unlisted host must fail: %+v", v)
	}
}

func TestSlowAndHugeSourcesDoNotHang(t *testing.T) {
	src := &source{body: enc(t, history(2)), delay: 1500 * time.Millisecond}
	c, _, _ := rig(t, src, func(o *Options) { o.Client = &http.Client{Timeout: 200 * time.Millisecond} })
	start := time.Now()
	c.CheckNow(context.Background())
	if time.Since(start) > 3*time.Second || c.View().State != "unavailable" {
		t.Errorf("a slow source must time out: %v %+v", time.Since(start), c.View())
	}
	huge := &source{body: make([]byte, MaxDocument+10)}
	c, _, _ = rig(t, huge, nil)
	c.CheckNow(context.Background())
	if v := c.View(); v.State != "unavailable" {
		t.Errorf("an oversized document: %+v", v)
	}
}

// The check never blocks the caller beyond its own call, and a second one while
// one runs does nothing.
func TestConcurrentChecksCollapse(t *testing.T) {
	src := &source{body: enc(t, history(2)), delay: 150 * time.Millisecond}
	c, _, _ := rig(t, src, nil)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.CheckNow(context.Background()) }()
	}
	wg.Wait()
	src.mu.Lock()
	n := len(src.requests)
	src.mu.Unlock()
	if n > 2 { // one document (and no signature request)
		t.Errorf("%d requests for concurrent checks", n)
	}
}
