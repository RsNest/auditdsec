package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// First-time setup.
//
// A new installation has no owner. Until one exists the panel accepts the
// well-known pair admin / admin, and what that buys is a short setup session
// which can finish the setup and do nothing else: every other call is refused
// by the server. The owner picks the real login and password there. Choosing
// them writes the managed credentials (hash only) and a completion marker.
//
// Once setup is complete nothing returns the panel to admin/admin: not a
// restart, a container update, a re-run of the installer or a lost browser.
// If the managed credentials are damaged or gone after completion, sign-in is
// refused with a diagnosis (state "locked"); restoring access is a local,
// explicit act: `auditdsec reset-credentials`.
const (
	credFile = "panel-credentials.json"
	doneFile = "panel-setup-done"

	setupSessionTTL = 15 * time.Minute
	globalFailLimit = 30 // wrong first sign-ins, from anywhere, per window
)

// State names reported by GET /api/v1/setup/state and used by the panel.
const (
	StateReady     = "ready"
	StateBootstrap = "bootstrap"
	StateLocked    = "locked"
)

type credsFile struct {
	Version            int    `json:"version"`
	Login              string `json:"login"`
	Hash               string `json:"hash"`
	BootstrapCompleted bool   `json:"bootstrap_completed"`
	Updated            string `json:"updated,omitempty"`
}

// ResetCredentials is the local recovery path: it removes the managed login
// and password and the completion marker, so the panel starts first-time setup again (admin / admin).
func ResetCredentials(stateDir string) error {
	for _, n := range []string{credFile, doneFile} {
		if err := os.Remove(filepath.Join(stateDir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func readJSON[T any](p string) (T, bool) {
	var v T
	b, err := os.ReadFile(p)
	if err != nil || json.Unmarshal(b, &v) != nil {
		return v, false
	}
	return v, true
}

// writeAtomic replaces dir/name with data (mode 0600) so that a crash leaves
// either the old file or the new one, never half of it.
func writeAtomic(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // make the rename itself durable
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// credState is the sign-in the server checks against once setup is complete.
type credState struct {
	mu     sync.RWMutex
	ready  bool
	login  string
	sum    [32]byte
	hash   parsedHash
	dummy  parsedHash
	locked string // why sign-in is stopped; empty when it is not
}

type credSnapshot struct {
	ready  bool
	sum    [32]byte
	hash   parsedHash
	dummy  parsedHash
	locked string
}

func (c *credState) snapshot() credSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return credSnapshot{c.ready, c.sum, c.hash, c.dummy, c.locked}
}

func (c *credState) set(login string, h parsedHash) error {
	d, err := decoyHash(h)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.ready, c.login, c.sum, c.hash, c.dummy, c.locked = true, login, sha256.Sum256([]byte(login)), h, d, ""
	c.mu.Unlock()
	return nil
}

func (c *credState) lock(why string) {
	c.mu.Lock()
	c.ready, c.locked = false, why
	c.mu.Unlock()
}

func (s *Server) path(name string) string {
	if s.opt.Config.StateDir == "" {
		return ""
	}
	return filepath.Join(s.opt.Config.StateDir, name)
}

// loadCreds decides, at start, who can sign in. Managed credentials win; an
// older password from the environment or the config file is migrated into
// them; with neither, the panel waits for first-time setup.
func (s *Server) loadCreds() error {
	w := s.opt.Config.Web
	cp, dp := s.path(credFile), s.path(doneFile)
	if cp != "" {
		b, err := os.ReadFile(cp)
		switch {
		case err == nil:
			var cf credsFile
			h, perr := parseHash("")
			if json.Unmarshal(b, &cf) == nil && cf.Login != "" {
				h, perr = parseHash(cf.Hash)
			} else {
				perr = errors.New("unreadable")
			}
			if perr != nil {
				s.cred.lock(fmt.Sprintf("%s is damaged", cp))
				s.log.Error("panel sign-in is stopped: the managed credentials are damaged; restore the file from a backup or run `auditdsec reset-credentials -yes` on this server", "file", cp)
				return nil
			}
			return s.cred.set(cf.Login, h)
		case !errors.Is(err, os.ErrNotExist):
			s.cred.lock(fmt.Sprintf("cannot read %s", cp))
			s.log.Error("panel sign-in is stopped: cannot read the managed credentials", "file", cp, "error", err)
			return nil
		}
		if exists(dp) {
			s.cred.lock(fmt.Sprintf("%s is missing although setup was completed", cp))
			s.log.Error("panel sign-in is stopped: setup was completed but the managed credentials are gone; restore the file or run `auditdsec reset-credentials -yes` on this server", "file", cp)
			return nil
		}
	}
	encoded := w.PasswordHash
	if encoded == "" && w.Password != "" {
		var err error
		if encoded, err = HashPassword(w.Password); err != nil {
			return err
		}
	}
	if encoded == "" {
		return nil // first-time setup
	}
	h, err := parseHash(encoded)
	if err != nil {
		return fmt.Errorf("api: web.password_hash: %w", err)
	}
	login := strings.TrimSpace(w.Login)
	if err := s.cred.set(login, h); err != nil {
		return err
	}
	// An installation that already had its own password keeps it. It becomes
	// the managed credentials, so a later change in the panel is not undone
	// by the old environment value at the next start.
	if cp != "" {
		if err := s.persist(login, encoded); err != nil {
			s.log.Warn("could not copy the configured panel password into the managed credentials; the configured one stays in force", "error", err)
		}
	}
	return nil
}

func (s *Server) persist(login, hash string) error {
	b, _ := json.Marshal(credsFile{Version: 1, Login: login, Hash: hash, BootstrapCompleted: true, Updated: s.now().UTC().Format(time.RFC3339)})
	if err := writeAtomic(s.opt.Config.StateDir, credFile, b); err != nil {
		return err
	}
	return writeAtomic(s.opt.Config.StateDir, doneFile, []byte("1\n"))
}

// bootstrapState reports where first-time setup stands.
func (s *Server) bootstrapState() string {
	snap := s.cred.snapshot()
	switch {
	case snap.locked != "":
		return StateLocked
	case snap.ready:
		return StateReady
	}
	return StateBootstrap
}

func (s *Server) handleSetupState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"state": s.bootstrapState()})
}

// bootstrapLogin handles a sign-in while setup is pending: only admin / admin
// is accepted, both compared in constant time, and a wrong anything gives the
// same answer. The result is a setup session, not a panel session.
func (s *Server) bootstrapLogin(w http.ResponseWriter, ip, login, password string) {
	if s.bootstrapState() == StateLocked {
		fail(w, http.StatusServiceUnavailable, "credentials_unavailable",
			"sign-in is stopped: the saved login and password cannot be read; see the agent log")
		return
	}
	if blocked, wait := s.global.blocked("*"); blocked {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		fail(w, http.StatusTooManyRequests, "throttled", "too many attempts, try later")
		return
	}
	okLogin := subtle.ConstantTimeCompare([]byte(login), []byte(DefaultLogin))
	okPass := subtle.ConstantTimeCompare([]byte(password), []byte(DefaultPassword))
	if okLogin&okPass != 1 {
		s.limit.failed(ip)
		s.global.failed("*")
		s.log.Warn("panel first sign-in failed", "ip", ip)
		fail(w, http.StatusUnauthorized, "bad_credentials", "wrong login or password")
		return
	}
	s.limit.ok(ip)
	token, exp := s.sessions.createKind(kindSetup, 0, setupSessionTTL)
	s.log.Info("panel setup session opened: the default login must be replaced", "ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires": exp.UTC().Format(time.RFC3339), "setup": true})
}

// handleSetupComplete finishes first-time setup. Only a setup session of the
// current bootstrap generation may call it; the server checks every rule
// itself, whatever the page did.
func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessions.lookup(bearer(r))
	if !ok || sess.kind != kindSetup {
		fail(w, http.StatusUnauthorized, "unauthorized", "sign in first")
		return
	}
	var in struct {
		Login              string `json:"login"`
		Password           string `json:"password"`
		PasswordConfirm    string `json:"password_confirm"`
		KeepAdminConfirmed bool   `json:"keep_admin_confirmed"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.finalizeMu.Lock() // two requests cannot each install a different pair
	defer s.finalizeMu.Unlock()

	if s.bootstrapState() != StateBootstrap {
		s.sessions.revoke(bearer(r))
		fail(w, http.StatusUnauthorized, "unauthorized", "the setup session is no longer valid; start again")
		return
	}
	login := strings.TrimSpace(in.Login)
	var reasons []string
	reasons = append(reasons, CheckLogin(login, in.KeepAdminConfirmed)...)
	reasons = append(reasons, CheckPassword(in.Password, login)...)
	if in.Password != in.PasswordConfirm {
		reasons = append(reasons, ReasonMismatch)
	}
	if len(reasons) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "weak_credentials", "message": "the login or password is not acceptable", "reasons": reasons})
		return
	}
	enc, err := HashPassword(in.Password)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "cannot hash the password")
		return
	}
	if s.path(credFile) == "" {
		fail(w, http.StatusInternalServerError, "bootstrap_persistence_failed", "there is no place to save the login and password")
		return
	}
	if err := s.persist(login, enc); err != nil {
		s.log.Error("cannot save the panel credentials; setup stays unfinished", "error", err)
		fail(w, http.StatusInternalServerError, "bootstrap_persistence_failed", "cannot save the login and password; setup is not finished")
		return
	}
	h, _ := parseHash(enc)
	if err := s.cred.set(login, h); err != nil {
		fail(w, http.StatusInternalServerError, "internal", "cannot apply the new credentials")
		return
	}
	// The first session and every other one end here.
	s.sessions.revokeAll()
	s.log.Info("panel setup complete; sign in with the new login and password")
	w.WriteHeader(http.StatusNoContent)
}

// SetupState says whether first-time setup is pending ("bootstrap"), done
// ("ready") or blocked ("locked"), for the startup log.
func (s *Server) SetupState() string { return s.bootstrapState() }
