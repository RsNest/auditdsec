package i18n

import (
	"reflect"
	"strings"
	"testing"
)

// Every language must carry every key, so switching language can never produce
// a message that falls back to a raw key.
func TestCatalogsHaveSameKeys(t *testing.T) {
	ru := Keys(LangRU)
	en := Keys(LangEN)
	if !reflect.DeepEqual(ru, en) {
		missingEN := diff(ru, en)
		missingRU := diff(en, ru)
		if len(missingEN) > 0 {
			t.Errorf("keys missing from the en catalog: %v", missingEN)
		}
		if len(missingRU) > 0 {
			t.Errorf("keys missing from the ru catalog: %v", missingRU)
		}
	}
}

// A translation that drops or renames a placeholder would silently print
// "{user}" to a user, so the placeholder sets must match exactly.
func TestCatalogsHaveSamePlaceholders(t *testing.T) {
	for _, k := range Keys(LangRU) {
		ru := Placeholders(catalogRU[k])
		en := Placeholders(catalogEN[k])
		if !reflect.DeepEqual(ru, en) {
			t.Errorf("key %q: placeholders differ: ru=%v en=%v", k, ru, en)
		}
	}
}

func TestEveryKindHasSummaryAndExplain(t *testing.T) {
	kinds := []string{
		"ssh_login_ok", "ssh_login_fail", "sudo", "user_change",
		"authorized_keys_change", "persistence", "config_change",
		"log_tamper", "suspicious_exec", "auditd_stopped",
	}
	for _, lang := range Langs() {
		for _, k := range kinds {
			for _, prefix := range []string{"event.", "explain."} {
				if !Has(lang, prefix+k) {
					t.Errorf("lang %s: missing key %s%s", lang, prefix, k)
				}
			}
		}
	}
}

func TestT(t *testing.T) {
	got := T(LangRU, "event.ssh_login_ok", map[string]string{"user": "root", "ip": "1.2.3.4"})
	want := "Вход в систему: root с адреса 1.2.3.4"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	got = T(LangEN, "event.ssh_login_ok", map[string]string{"user": "root", "ip": "1.2.3.4"})
	if got != "Login: root from 1.2.3.4" {
		t.Errorf("en: got %q", got)
	}
}

func TestTUnknownKeyReturnsKey(t *testing.T) {
	if got := T(LangRU, "nope.nothing", nil); got != "nope.nothing" {
		t.Errorf("got %q", got)
	}
}

func TestTFallsBackToDefaultLanguage(t *testing.T) {
	// A language that does not exist still renders through the default.
	got := T(Lang("de"), "ui.never", nil)
	if got != catalogRU["ui.never"] {
		t.Errorf("got %q, want fallback to ru", got)
	}
}

func TestTKeepsUnknownPlaceholderVisible(t *testing.T) {
	got := T(LangRU, "event.ssh_login_ok", map[string]string{"user": "root"})
	if !strings.Contains(got, "{ip}") {
		t.Errorf("unknown placeholder should stay visible, got %q", got)
	}
}

func TestParseLang(t *testing.T) {
	tests := map[string]struct {
		want Lang
		err  bool
	}{
		"":     {Default, false},
		"ru":   {LangRU, false},
		"EN":   {LangEN, false},
		" en ": {LangEN, false},
		"de":   {Default, true},
	}
	for in, tc := range tests {
		got, err := ParseLang(in)
		if (err != nil) != tc.err {
			t.Errorf("ParseLang(%q) error = %v, want error %v", in, err, tc.err)
		}
		if got != tc.want {
			t.Errorf("ParseLang(%q) = %q, want %q", in, got, tc.want)
		}
	}
}

func TestPlaceholders(t *testing.T) {
	got := Placeholders("a {x} b {y} c {x}")
	if !reflect.DeepEqual(got, []string{"x", "y"}) {
		t.Errorf("got %v", got)
	}
	if got := Placeholders("no placeholders"); len(got) != 0 {
		t.Errorf("got %v", got)
	}
	// Unbalanced braces must not panic or loop.
	if got := Placeholders("{unclosed"); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func diff(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, s := range b {
		set[s] = true
	}
	var out []string
	for _, s := range a {
		if !set[s] {
			out = append(out, s)
		}
	}
	return out
}
