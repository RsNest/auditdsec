package api

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// The rules for a login and a password chosen by the owner. One function
// serves the setup endpoint, `auditdsec hash-password`, the installer (through
// that command) and the browser, whose copy of the rules lives in
// internal/web/assets/views.js and is only a convenience: the server decides.
const (
	MinPasswordRunes = 8
	MaxPasswordRunes = 128
	MinLoginRunes    = 3
	MaxLoginRunes    = 64
	DefaultLogin     = "admin"
	DefaultPassword  = "admin"
)

// Reasons are stable slugs: the panel turns them into sentences in the
// owner's language.
const (
	ReasonShort       = "password_short"
	ReasonLong        = "password_long"
	ReasonNeedLower   = "password_need_lower"
	ReasonNeedUpper   = "password_need_upper"
	ReasonDefault     = "password_default"
	ReasonSameAsLogin = "password_same_as_login"
	ReasonCommon      = "password_common"
	ReasonMismatch    = "password_mismatch"
	ReasonLoginLen    = "login_length"
	ReasonLoginChars  = "login_chars"
	ReasonKeepAdmin   = "login_admin_unconfirmed"
)

// commonPasswords is deliberately small: it catches the passwords that every
// guessing list starts with, not every weak one. Compared in lower case.
var commonPasswords = map[string]bool{
	"password": true, "password1": true, "password123": true, "passw0rd": true, "p@ssw0rd": true,
	"qwerty": true, "qwerty123": true, "qwertyuiop": true, "qwerty1": true, "1qaz2wsx": true,
	"12345678": true, "123456789": true, "1234567890": true, "11111111": true, "00000000": true,
	"abc12345": true, "abcd1234": true, "iloveyou": true, "letmein": true, "welcome": true,
	"welcome1": true, "welcome123": true, "administrator": true, "admin123": true, "admin1234": true,
	"adminadmin": true, "changeme": true, "changeme123": true, "master": true, "monkey123": true,
	"dragon": true, "football": true, "baseball": true, "sunshine": true, "princess": true,
	"trustno1": true, "superman": true, "shadow": true, "login": true, "root": true,
	"rootroot": true, "toor": true, "test1234": true, "testtest": true, "default": true,
	"auditdsec": true, "ubuntu": true, "debian": true, "centos": true, "server": true,
	"йцукен": true, "пароль": true, "пароль1": true, "qazwsxedc": true, "zaq12wsx": true,
}

// CheckPassword returns the reasons a password is not acceptable; none means
// it is. login is the account name it will be used with.
func CheckPassword(password, login string) []string {
	var out []string
	n := utf8.RuneCountInString(password)
	switch {
	case n < MinPasswordRunes:
		out = append(out, ReasonShort)
	case n > MaxPasswordRunes || len(password) > 4*MaxPasswordRunes:
		out = append(out, ReasonLong)
	}
	var lower, upper bool
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r) || unicode.IsTitle(r):
			upper = true
		}
	}
	if !lower {
		out = append(out, ReasonNeedLower)
	}
	if !upper {
		out = append(out, ReasonNeedUpper)
	}
	folded := strings.ToLower(password)
	switch {
	case folded == DefaultPassword:
		out = append(out, ReasonDefault)
	case commonPasswords[folded]:
		out = append(out, ReasonCommon)
	}
	if login != "" && folded == strings.ToLower(login) {
		out = append(out, ReasonSameAsLogin)
	}
	return out
}

// CheckLogin validates a new login. It is limited to a plain ASCII set so
// that two spellings of the same name cannot exist (no Unicode normalisation
// is needed) and so it is safe in HTML, a log line and a shell. keepAdmin is
// the owner's explicit confirmation that "admin" stays.
func CheckLogin(login string, keepAdmin bool) []string {
	var out []string
	n := utf8.RuneCountInString(login)
	if n < MinLoginRunes || n > MaxLoginRunes {
		out = append(out, ReasonLoginLen)
	}
	for _, r := range login {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || r == '@'
		if !ok {
			out = append(out, ReasonLoginChars)
			break
		}
	}
	if strings.EqualFold(login, DefaultLogin) && !keepAdmin {
		out = append(out, ReasonKeepAdmin)
	}
	return out
}
