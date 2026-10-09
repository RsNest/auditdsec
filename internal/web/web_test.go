package web

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func serve(t *testing.T, method, target string, headers map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	return rec.Result()
}

func TestServesIndexAtRoot(t *testing.T) {
	res := serve(t, http.MethodGet, "/", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := res.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("content type = %q, want html", got)
	}
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "ETag"} {
		if res.Header.Get(h) == "" {
			t.Errorf("header %s is missing", h)
		}
	}
	if csp := res.Header.Get("Content-Security-Policy"); strings.Contains(csp, "unsafe-inline") {
		t.Errorf("the policy allows inline code: %q", csp)
	}
}

func TestSinglePageFallback(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"/events", "text/html"},
		{"/bans", "text/html"},
		{"/app.css", "text/css"},
		{"/core.js", "text/javascript"},
		{"/i18n.js", "text/javascript"},
	}
	for _, c := range cases {
		res := serve(t, http.MethodGet, c.target, nil)
		if res.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", c.target, res.StatusCode)
			continue
		}
		if got := res.Header.Get("Content-Type"); !strings.HasPrefix(got, c.want) {
			t.Errorf("%s: content type = %q, want %s", c.target, got, c.want)
		}
	}
}

func TestMissingFileIsNotFound(t *testing.T) {
	res := serve(t, http.MethodGet, "/nope.js", nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
}

// Demo data must never reach a real agent: it would show events that did not
// happen, which is worse than showing none.
func TestMockDataIsNotEmbedded(t *testing.T) {
	if _, ok := assets["dev/mock.js"]; ok {
		t.Fatal("dev/mock.js is embedded in the binary")
	}
	res := serve(t, http.MethodGet, "/dev/mock.js", nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	res := serve(t, http.MethodPost, "/", nil)
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", res.StatusCode)
	}
	if got := res.Header.Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q", got)
	}
}

func TestNotModified(t *testing.T) {
	first := serve(t, http.MethodGet, "/app.css", nil)
	etag := first.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on the first response")
	}
	second := serve(t, http.MethodGet, "/app.css", map[string]string{"If-None-Match": etag})
	if second.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", second.StatusCode)
	}
	third := serve(t, http.MethodGet, "/app.css", map[string]string{"If-None-Match": `"stale"`})
	if third.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a stale validator", third.StatusCode)
	}
}

func TestEscapesOutOfTheAssetTree(t *testing.T) {
	res := serve(t, http.MethodGet, "/../web.go", nil)
	if res.StatusCode == http.StatusOK {
		ct := res.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("a path escape served %q", ct)
		}
	}
}

// The page may hold nothing executable of its own, because the content policy
// refuses inline code and a panel that silently does not work is worse than
// one that fails loudly in a test.
func TestIndexHasNoInlineCode(t *testing.T) {
	body := string(assets[indexFile].body)
	for _, bad := range []string{" onclick=", " onload=", " onerror=", " style=", "javascript:"} {
		if strings.Contains(body, bad) {
			t.Errorf("index.html contains %q", bad)
		}
	}
	if regexp.MustCompile(`(?s)<script[^>]*>\s*[^\s<]`).MatchString(body) {
		t.Error("index.html contains an inline script body")
	}
}

func TestAssetBudget(t *testing.T) {
	const budget = 150 * 1024
	total := 0
	for name, a := range assets {
		total += len(a.body)
		if len(a.body) == 0 {
			t.Errorf("%s is empty", name)
		}
	}
	if total > budget {
		t.Fatalf("embedded assets are %d bytes, over the %d budget", total, budget)
	}
}

func TestEverySourceFileIsEmbedded(t *testing.T) {
	want := []string{"app.css", "core.js", "i18n.js", "index.html", "views.js"}
	var got []string
	for name := range assets {
		got = append(got, name)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("embedded set = %v, want %v", got, want)
	}
}

// The two catalogues are the UI's whole vocabulary. A key present in one
// language only shows up as a raw key on screen, so the test is the guard.
func TestCataloguesMatch(t *testing.T) {
	src, err := fs.ReadFile(FS(), "i18n.js")
	if err != nil {
		t.Fatalf("cannot read i18n.js: %v", err)
	}
	text := string(src)
	start, end := strings.Index(text, "{"), strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		t.Fatal("i18n.js holds no object literal")
	}
	var catalogues map[string]map[string]string
	if err := json.Unmarshal([]byte(text[start:end+1]), &catalogues); err != nil {
		t.Fatalf("the catalogues are not valid JSON (keep them JSON so this test can read them): %v", err)
	}
	ru, ok := catalogues["ru"]
	if !ok || len(ru) == 0 {
		t.Fatal("the russian catalogue is missing or empty")
	}
	en, ok := catalogues["en"]
	if !ok {
		t.Fatal("the english catalogue is missing")
	}
	for key := range ru {
		if _, ok := en[key]; !ok {
			t.Errorf("key %q is missing from the english catalogue", key)
		}
	}
	for key := range en {
		if _, ok := ru[key]; !ok {
			t.Errorf("key %q is missing from the russian catalogue", key)
		}
	}
	placeholder := regexp.MustCompile(`{(\w+)}`)
	for key, text := range ru {
		other, ok := en[key]
		if !ok {
			continue
		}
		a, b := placeholder.FindAllString(text, -1), placeholder.FindAllString(other, -1)
		sort.Strings(a)
		sort.Strings(b)
		if strings.Join(a, "") != strings.Join(b, "") {
			t.Errorf("key %q has placeholders %v in russian and %v in english", key, a, b)
		}
	}
}
