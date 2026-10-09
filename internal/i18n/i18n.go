// Package i18n renders user-facing text. Russian is the default language and
// English is kept complete alongside it; a test enforces that both catalogs
// carry the same keys and the same placeholders.
package i18n

import (
	"fmt"
	"sort"
	"strings"
)

// Lang is a supported UI language.
type Lang string

const (
	LangRU Lang = "ru"
	LangEN Lang = "en"

	// Default is the language used when none is configured.
	Default = LangRU
)

var catalogs = map[Lang]map[string]string{
	LangRU: catalogRU,
	LangEN: catalogEN,
}

// Langs returns the supported languages, sorted.
func Langs() []Lang {
	out := make([]Lang, 0, len(catalogs))
	for l := range catalogs {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ParseLang validates a language code from the config file or environment.
func ParseLang(s string) (Lang, error) {
	l := Lang(strings.ToLower(strings.TrimSpace(s)))
	if l == "" {
		return Default, nil
	}
	if _, ok := catalogs[l]; !ok {
		return Default, fmt.Errorf("unsupported language %q (want ru or en)", s)
	}
	return l, nil
}

// T renders the template stored under key, substituting {name} placeholders
// from args. A missing key falls back to the default language and then to the
// key itself, so a half-translated build degrades instead of printing nothing.
func T(lang Lang, key string, args map[string]string) string {
	tpl, ok := lookup(lang, key)
	if !ok {
		return key
	}
	return expand(tpl, args)
}

// Has reports whether the key exists for the language.
func Has(lang Lang, key string) bool {
	_, ok := catalogs[lang][key]
	return ok
}

// Keys lists every key of a catalog, sorted.
func Keys(lang Lang) []string {
	c := catalogs[lang]
	out := make([]string, 0, len(c))
	for k := range c {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func lookup(lang Lang, key string) (string, bool) {
	if c, ok := catalogs[lang]; ok {
		if tpl, ok := c[key]; ok {
			return tpl, true
		}
	}
	if lang != Default {
		if tpl, ok := catalogs[Default][key]; ok {
			return tpl, true
		}
	}
	return "", false
}

// expand replaces {name} with args[name]. Unknown placeholders are left in
// place: a visible {oops} in a message is easier to notice and fix than a
// silently empty sentence.
func expand(tpl string, args map[string]string) string {
	if !strings.ContainsRune(tpl, '{') {
		return tpl
	}
	var b strings.Builder
	b.Grow(len(tpl))
	for {
		i := strings.IndexByte(tpl, '{')
		if i < 0 {
			b.WriteString(tpl)
			return b.String()
		}
		j := strings.IndexByte(tpl[i:], '}')
		if j < 0 {
			b.WriteString(tpl)
			return b.String()
		}
		j += i
		name := tpl[i+1 : j]
		b.WriteString(tpl[:i])
		if v, ok := args[name]; ok {
			b.WriteString(v)
		} else {
			b.WriteString(tpl[i : j+1])
		}
		tpl = tpl[j+1:]
	}
}

// Placeholders returns the placeholder names used by a template, sorted and
// de-duplicated. Used by tests to keep translations in sync.
func Placeholders(tpl string) []string {
	seen := map[string]bool{}
	for {
		i := strings.IndexByte(tpl, '{')
		if i < 0 {
			break
		}
		j := strings.IndexByte(tpl[i:], '}')
		if j < 0 {
			break
		}
		j += i
		seen[tpl[i+1:j]] = true
		tpl = tpl[j+1:]
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
