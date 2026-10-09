// Package web serves the panel's static assets out of the binary.
//
// The files are embedded, so a running agent needs nothing on disk and the
// panel cannot be tampered with by editing a directory. Only the production
// set is embedded: assets/dev/mock.js holds demo data and stays out, so the
// agent can never serve made-up events.
//
// The handler is deliberately dumb: it answers GET and HEAD for the embedded
// files, falls back to index.html for the single-page routes, and sets the
// headers that keep a panel built from attacker-controlled log lines boring —
// a content policy that forbids inline script, no framing, no referrers.
package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed assets/index.html assets/app.css assets/core.js assets/feed.js assets/views.js assets/i18n.js assets/fonts/*.woff2
var embedded embed.FS

// contentSecurityPolicy allows exactly what the panel uses: its own scripts,
// styles and XHR, plus the inline SVG favicon. Everything else, inline script
// included, is refused by the browser, which is the cheap half of the defence
// against a crafted audit log line.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; " +
	"form-action 'none'; frame-ancestors 'none'"

const indexFile = "index.html"

type asset struct {
	body        []byte
	contentType string
	etag        string
}

var assets = map[string]asset{}

// FS exposes the embedded files, so a caller can serve them itself.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "assets")
	if err != nil {
		panic("web: assets missing from the binary: " + err.Error())
	}
	return sub
}

func init() {
	sub := FS()
	err := fs.WalkDir(sub, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := fs.ReadFile(sub, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		assets[name] = asset{
			body:        body,
			contentType: mediaType(name),
			etag:        `"` + hex.EncodeToString(sum[:8]) + `"`,
		}
		return nil
	})
	if err != nil {
		panic("web: cannot read embedded assets: " + err.Error())
	}
	if _, ok := assets[indexFile]; !ok {
		panic("web: index.html missing from the binary")
	}
}

func mediaType(name string) string {
	switch path.Ext(name) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".woff2":
		return "font/woff2"
	default:
		return "application/octet-stream"
	}
}

// Handler serves the panel. Unknown paths without a file extension are the
// app's own hash-free routes, so they get index.html; a missing file with an
// extension is a real 404 and says so, because silently answering HTML to a
// request for a script is how blank pages happen.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || name == "." {
			name = indexFile
		}
		a, ok := assets[name]
		if !ok {
			if path.Ext(name) != "" {
				security(w)
				http.NotFound(w, r)
				return
			}
			a = assets[indexFile]
			name = indexFile
		}

		security(w)
		w.Header().Set("Content-Type", a.contentType)
		w.Header().Set("ETag", a.etag)
		// The assets ship with the binary, so a version is only ever as stale
		// as the agent: revalidate every time and answer 304 almost always.
		w.Header().Set("Cache-Control", "no-cache")
		if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, a.etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(a.body))
	})
}

func security(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
}

func etagMatches(header, etag string) bool {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "W/")
		if part == "*" || part == etag {
			return true
		}
	}
	return false
}
