package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// The panel starts with one well-known account, admin / admin, when nobody
// has configured a password. That account can do exactly one thing: change
// itself. Every other endpoint answers 403 until the login and the password
// have both been replaced, so the default can be used to take the panel over
// only by someone who then has to pick the real credentials.
const (
	DefaultLogin    = "admin"
	DefaultPassword = "admin"

	credFile      = "panel-credentials.json"
	minNewPassLen = 12
	maxLoginLen   = 64
)

var errCredentials = errors.New("credentials")

// credState is the sign-in the server checks against. It changes at runtime,
// when the owner replaces the default account.
type credState struct {
	mu        sync.RWMutex
	login     string
	loginSum  [32]byte
	hash      parsedHash
	dummy     parsedHash
	mustReset bool
}

type credSnapshot struct {
	loginSum  [32]byte
	hash      parsedHash
	dummy     parsedHash
	mustReset bool
}

func (c *credState) snapshot() credSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return credSnapshot{c.loginSum, c.hash, c.dummy, c.mustReset}
}

func (c *credState) set(login string, h parsedHash, must bool) error {
	d, err := decoyHash(h)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.login, c.loginSum, c.hash, c.dummy, c.mustReset = login, sha256.Sum256([]byte(login)), h, d, must
	c.mu.Unlock()
	return nil
}

func (c *credState) mustChange() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mustReset
}

type storedCreds struct {
	Login string `json:"login"`
	Hash  string `json:"hash"`
}

// loadCreds picks the credentials at start: a file written by a password
// change wins, then the configuration, and with neither the default account.
func (s *Server) loadCreds() error {
	w := s.opt.Config.Web
	if p := s.credPath(); p != "" {
		b, err := os.ReadFile(p)
		switch {
		case err == nil:
			var sc storedCreds
			if err := json.Unmarshal(b, &sc); err != nil || sc.Login == "" {
				return fmt.Errorf("api: %s is damaged: remove it to go back to the default account", p)
			}
			h, err := parseHash(sc.Hash)
			if err != nil {
				return fmt.Errorf("api: %s: %w", p, err)
			}
			return s.cred.set(sc.Login, h, false)
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("api: cannot read %s: %w", p, err)
		}
	}
	encoded := w.PasswordHash
	if encoded == "" && w.Password != "" {
		var err error
		if encoded, err = HashPassword(w.Password); err != nil {
			return err
		}
	}
	if encoded != "" {
		h, err := parseHash(encoded)
		if err != nil {
			return fmt.Errorf("api: web.password_hash: %w", err)
		}
		return s.cred.set(w.Login, h, false)
	}
	h, err := parseHash(mustHash(DefaultPassword))
	if err != nil {
		return err
	}
	s.log.Warn("panel is using the default account admin/admin: it can only change its own credentials")
	return s.cred.set(DefaultLogin, h, true)
}

func mustHash(p string) string {
	h, err := HashPassword(p)
	if err != nil {
		panic("api: " + err.Error())
	}
	return h
}

func (s *Server) credPath() string {
	if s.opt.Config.StateDir == "" {
		return ""
	}
	return filepath.Join(s.opt.Config.StateDir, credFile)
}

// saveCreds writes the new sign-in atomically with mode 0600 and removes
// nothing: the hash is the only thing stored, never the password.
func (s *Server) saveCreds(login, hash string) error {
	p := s.credPath()
	if p == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(storedCreds{Login: login, Hash: hash})
	tmp, err := os.CreateTemp(filepath.Dir(p), ".cred-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// checkNewCreds is the whole policy for a replacement account.
func checkNewCreds(login, password, oldPassword string) string {
	login = strings.TrimSpace(login)
	switch {
	case login == "" || utf8.RuneCountInString(login) > maxLoginLen:
		return "login: 1 to 64 characters"
	case strings.IndexFunc(login, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
		return "login: no spaces or control characters"
	case strings.EqualFold(login, DefaultLogin):
		return "login: choose a login other than admin"
	case utf8.RuneCountInString(password) < minNewPassLen:
		return fmt.Sprintf("password: at least %d characters", minNewPassLen)
	case len(password) > 256:
		return "password: too long"
	case strings.EqualFold(password, DefaultPassword) || password == oldPassword:
		return "password: choose a new password"
	case strings.EqualFold(password, login):
		return "password: must differ from the login"
	}
	return ""
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if blocked, wait := s.limit.blocked(ip); blocked {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		fail(w, 429, "throttled", "too many attempts, try later")
		return
	}
	var in struct {
		Current  string `json:"current_password"`
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Current) > 256 {
		fail(w, 400, "bad_request", "too long")
		return
	}
	select {
	case s.hashing <- struct{}{}:
		defer func() { <-s.hashing }()
	default:
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "throttled", "busy, try again")
		return
	}
	snap := s.cred.snapshot()
	if !snap.hash.verify(in.Current) {
		s.limit.failed(ip)
		fail(w, 400, "wrong_password", "the current password is wrong")
		return
	}
	if msg := checkNewCreds(in.Login, in.Password, in.Current); msg != "" {
		fail(w, 400, "weak_credentials", msg)
		return
	}
	login := strings.TrimSpace(in.Login)
	enc, err := HashPassword(in.Password)
	if err != nil {
		fail(w, 500, "internal", "cannot hash the password")
		return
	}
	if err := s.saveCreds(login, enc); err != nil {
		s.log.Error("cannot save the new panel credentials", "error", err)
		fail(w, 500, "internal", "cannot save the new credentials")
		return
	}
	h, _ := parseHash(enc)
	if err := s.cred.set(login, h, false); err != nil {
		fail(w, 500, "internal", "cannot apply the new credentials")
		return
	}
	s.sessions.revokeAll()
	s.limit.ok(ip)
	s.log.Info("panel credentials changed", "ip", ip)
	w.WriteHeader(204)
}
