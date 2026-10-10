package session

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type saved struct {
	Version  int               `json:"version"`
	BootID   string            `json:"boot_id"`
	Sessions []entry           `json:"sessions"`
	Names    map[string]string `json:"names,omitempty"`
}

// Dirty reports whether the table changed since the last Save.
func (t *Tracker) Dirty() bool { t.mu.Lock(); defer t.mu.Unlock(); return t.dirty }

// Save writes the table atomically. The journal lines are not saved: they are
// re-read from the journal, which is their source of truth.
func (t *Tracker) Save(path string) error {
	t.mu.Lock()
	t.evict()
	s := saved{Version: 1, BootID: t.bootID, Names: map[string]string{}}
	for _, e := range t.sessions {
		s.Sessions = append(s.Sessions, *e)
	}
	for k, v := range t.names {
		s.Names[k] = v
	}
	t.mu.Unlock()
	sort.Slice(s.Sessions, func(i, j int) bool { return s.Sessions[i].Ses < s.Sessions[j].Ses })
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sessions-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		_ = os.Remove(name)
		return werr
	}
	t.mu.Lock()
	t.dirty = false
	t.mu.Unlock()
	return nil
}

// Load restores the table from path. A table written in another boot is
// discarded, because audit session IDs restart at a reboot; a missing file is
// an empty table. A damaged file is reported and ignored: the table is
// rebuilt from the audit log as it is read.
func (t *Tracker) Load(path string) (discarded bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var s saved
	if err := json.Unmarshal(data, &s); err != nil {
		return false, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if s.BootID != "" && t.bootID != "" && s.BootID != t.bootID {
		return true, nil
	}
	for i := range s.Sessions {
		e := s.Sessions[i]
		if validID(e.Ses) && validID(e.LoginUID) {
			t.sessions[e.Ses] = &e
		}
	}
	for k, v := range s.Names {
		if validID(k) || k == "0" {
			t.learnName(k, v)
		}
	}
	t.evict()
	return false, nil
}

// ReadBootID returns the kernel boot ID, or "" where it cannot be read
// (not Linux, or /proc hidden). Without it a reboot is only noticed through
// SYSTEM_BOOT records.
func ReadBootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
