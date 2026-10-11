// Package update tells an installed auditdsec whether a newer published version
// exists, and what changed in it. It never updates anything: applying a new
// version is the installer's job (./install.sh), with the checks and the
// rollback that already live there.
//
// The source is a small JSON document per channel, published by CI only after
// the tests passed, every image was pushed and anonymously pulled. It is fetched
// over HTTPS from a fixed set of hosts and, when a signing key is built in,
// must carry a valid Ed25519 signature. The request carries nothing about the
// server, its events or its user.
package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Channels.
const (
	ChannelStable = "stable" // tagged releases
	ChannelMain   = "main"   // every build of the main branch that passed CI
)

// Text is a string in both product languages.
type Text struct {
	EN string `json:"en"`
	RU string `json:"ru"`
}

// Lang returns the text for "ru", else English.
func (t Text) Lang(lang string) string {
	if lang == "ru" && t.RU != "" {
		return t.RU
	}
	return t.EN
}

// Lists is a list of short sentences in both languages.
type Lists struct {
	EN []string `json:"en"`
	RU []string `json:"ru"`
}

// Lang returns the list for "ru", else English.
func (l Lists) Lang(lang string) []string {
	if lang == "ru" && len(l.RU) > 0 {
		return l.RU
	}
	return l.EN
}

// Requires are the conditions of applying an entry's changes.
type Requires struct {
	// InstallerUpdate: the installer scripts or Compose files change, so the
	// update replaces them (with a diff and a backup).
	InstallerUpdate bool `json:"installer_update"`
	// Migration: none, reversible or irreversible. An irreversible one is
	// preceded by a backup of the data.
	Migration string `json:"migration"`
}

// Entry is the reviewed description of one change set.
type Entry struct {
	ID       string   `json:"id"`
	Date     string   `json:"date"`
	Title    Text     `json:"title"`
	Added    Lists    `json:"added"`
	Fixed    Lists    `json:"fixed"`
	Changed  Lists    `json:"changed"`
	Actions  Lists    `json:"actions"`
	Breaking []Text   `json:"breaking"`
	Requires Requires `json:"requires"`
}

// ImageRef is one published image.
type ImageRef struct {
	Ref       string   `json:"ref"`
	Digest    string   `json:"digest"`
	Platforms []string `json:"platforms"`
}

// Build is one publication, in the order they were published.
type Build struct {
	Seq       int                 `json:"seq"` // grows by one per publication: the order, never a SHA comparison
	Version   string              `json:"version"`
	Commit    string              `json:"commit"`
	Published string              `json:"published"`
	Images    map[string]ImageRef `json:"images,omitempty"`
	Entries   []Entry             `json:"entries"` // the entries first shipped in this build
}

// Metadata is the document of a channel. Builds are newest first.
type Metadata struct {
	Schema      int     `json:"schema"`
	Channel     string  `json:"channel"`
	Repo        string  `json:"repo"`
	GeneratedAt string  `json:"generated_at"`
	Builds      []Build `json:"builds"`
}

// Latest is the newest build.
func (m Metadata) Latest() Build { return m.Builds[0] }

var (
	shaRe     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	platformR = regexp.MustCompile(`^linux/(amd64|arm64|arm|386|riscv64|s390x|ppc64le)(/v[0-9])?$`)
	entryIDRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}-[a-z0-9][a-z0-9-]{2,60}$`)
)

// Limits on what the checker accepts, so a bad document cannot exhaust memory
// or fill the screen.
const (
	MaxDocument = 512 << 10
	maxBuilds   = 100
	maxText     = 600
	maxItems    = 16
)

// ErrInvalid wraps every problem with a document.
var ErrInvalid = errors.New("invalid update metadata")

func bad(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(f, a...)) }

// Parse decodes and validates a document.
func Parse(data []byte) (Metadata, error) {
	if len(data) > MaxDocument {
		return Metadata{}, bad("document is too large")
	}
	var m Metadata
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&m); err != nil {
		return Metadata{}, bad("not JSON")
	}
	if err := m.validate(); err != nil {
		return Metadata{}, err
	}
	return m, nil
}

func checkText(what, s string) error {
	if len(s) > maxText {
		return bad("%s is too long", what)
	}
	return nil
}

func (m Metadata) validate() error {
	if m.Schema != 1 {
		return bad("unsupported schema %d", m.Schema)
	}
	if m.Channel != ChannelStable && m.Channel != ChannelMain {
		return bad("unknown channel %q", m.Channel)
	}
	if len(m.Builds) == 0 || len(m.Builds) > maxBuilds {
		return bad("the number of builds must be 1..%d", maxBuilds)
	}
	prev := 0
	seen := map[string]bool{}
	for i, b := range m.Builds {
		if b.Seq < 1 || (i > 0 && b.Seq >= prev) {
			return bad("build sequence numbers must be positive and strictly decreasing")
		}
		prev = b.Seq
		if !shaRe.MatchString(b.Commit) || len(b.Version) == 0 || len(b.Version) > 64 {
			return bad("build %d has a bad commit or version", b.Seq)
		}
		if _, err := time.Parse(time.RFC3339, b.Published); err != nil {
			return bad("build %d has a bad publication time", b.Seq)
		}
		if i == 0 {
			a, ok := b.Images["auditdsec"]
			if !ok || !digestRe.MatchString(a.Digest) || !strings.HasPrefix(a.Ref, "ghcr.io/") || len(a.Platforms) == 0 {
				return bad("the latest build lacks a usable agent image")
			}
		}
		for name, img := range b.Images {
			if len(name) > 40 || !digestRe.MatchString(img.Digest) || !strings.HasPrefix(img.Ref, "ghcr.io/") || len(img.Ref) > 200 {
				return bad("build %d has a bad image %q", b.Seq, name)
			}
			for _, p := range img.Platforms {
				if !platformR.MatchString(p) {
					return bad("build %d has a bad platform %q", b.Seq, p)
				}
			}
		}
		if len(b.Entries) > maxItems {
			return bad("build %d has too many entries", b.Seq)
		}
		for _, e := range b.Entries {
			if !entryIDRe.MatchString(e.ID) || seen[e.ID] {
				return bad("bad or repeated entry %q", e.ID)
			}
			seen[e.ID] = true
			if err := validateEntry(e); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateEntry(e Entry) error {
	for _, t := range []string{e.Title.EN, e.Title.RU} {
		if err := checkText("a title", t); err != nil {
			return err
		}
	}
	for _, l := range []Lists{e.Added, e.Fixed, e.Changed, e.Actions} {
		if len(l.EN) > maxItems || len(l.RU) > maxItems {
			return bad("entry %s has too many items", e.ID)
		}
		for _, s := range append(append([]string{}, l.EN...), l.RU...) {
			if err := checkText("a note", s); err != nil {
				return err
			}
		}
	}
	if len(e.Breaking) > maxItems {
		return bad("entry %s has too many breaking changes", e.ID)
	}
	for _, b := range e.Breaking {
		if err := checkText("a breaking change", b.EN+b.RU); err != nil {
			return err
		}
	}
	switch e.Requires.Migration {
	case "", "none", "reversible", "irreversible":
	default:
		return bad("entry %s: unknown migration kind", e.ID)
	}
	return nil
}

// ParsePublicKey decodes a base64 Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("update: the public key must be 32 bytes of base64")
	}
	return ed25519.PublicKey(b), nil
}

// ErrSignature: the signature is missing or does not match.
var ErrSignature = errors.New("update: the metadata signature is missing or invalid")

// Verify checks a detached base64 signature of the exact document bytes.
func Verify(doc, sig []byte, pub ed25519.PublicKey) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, doc, raw) {
		return ErrSignature
	}
	return nil
}
