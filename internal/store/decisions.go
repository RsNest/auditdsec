package store

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/RsNest/auditdsec/internal/netaddr"
)

// Observed states of the enforcement of a ban. What a ban wants is implied by
// the record (active: the address should be blocked); these say what has been
// seen of the firewall, and never claim a block that was not made.
const (
	StatePending = "pending" // recorded, enforcement not attempted or not finished
	StateApplied = "applied" // the firewall holds the block; VerifiedAt says when it was last seen
	StateFailed  = "failed"  // the last attempt failed; LastError says why
	StateDryRun  = "dry_run" // the backend only logs what it would do
	StateUnknown = "unknown" // nothing enforces or reports: ban.backend is none, or the firewall cannot be queried
	StateExpired = "expired" // the ban ran out; nothing is wanted any more
)

// Release is an address whose block must be lifted although the record that
// asked for it is gone: after an unban or an allow the firewall may still
// hold the element until a removal succeeds.
type Release struct {
	IP        string    `json:"ip"`
	Since     time.Time `json:"since"`
	Reason    string    `json:"reason,omitempty"`
	Attempts  int       `json:"attempts,omitempty"`
	LastError string    `json:"last_error,omitempty"`
}

// ErrInvalidAddress is returned for text that is not an address.
var ErrInvalidAddress = errors.New("store: not an IP address")

// ErrAllowlisted is returned when a ban is refused because the address is
// allowlisted. Refusing here, in the store, means no caller can bypass it.
var ErrAllowlisted = fmt.Errorf("store: address is allowlisted")

// normalizeBan makes the legacy and the new fields agree.
func normalizeBan(b Ban) Ban {
	if b.State == "" {
		if b.Applied {
			b.State = StateApplied
		} else {
			b.State = StatePending
		}
	}
	b.Applied = b.State == StateApplied
	return b
}

// canonicalizeLocked rewrites keys that are not in canonical form (older
// versions stored text as it was typed). Colliding records keep the newer.
func (s *Store) canonicalizeLocked() {
	bans := make(map[string]Ban, len(s.state.Bans))
	for k, b := range s.state.Bans {
		key := k
		if c, err := netaddr.Canon(k); err == nil {
			key = c
		}
		b.IP = key
		b = normalizeBan(b)
		if old, ok := bans[key]; ok && old.CreatedAt.After(b.CreatedAt) {
			continue
		}
		bans[key] = b
	}
	s.state.Bans = bans

	allow := make(map[string]AllowEntry, len(s.state.Allowlist))
	for k, e := range s.state.Allowlist {
		key := k
		if en, err := netaddr.ParseEntry(k); err == nil {
			key = en.String()
		}
		e.IP = key
		if old, ok := allow[key]; ok && old.AddedAt.After(e.AddedAt) {
			continue
		}
		allow[key] = e
	}
	s.state.Allowlist = allow
	if s.state.Releases == nil {
		s.state.Releases = map[string]Release{}
	}
}

// Allow adds an address to the allowlist, so it can never be banned. This is
// what the "that was me" button does, and what protects an owner on a dynamic
// address from locking themselves out. It also removes an existing ban.
func (s *Store) Allow(ip, note string) error {
	_, _, err := s.AllowEntry(ip, note)
	return err
}

// AllowEntry adds an address or a CIDR network and returns the canonical key
// and the bans it removed. Each removed ban becomes a Release in the same
// write: the record is gone, the block in the firewall is not yet.
func (s *Store) AllowEntry(entry, note string) (string, []Ban, error) {
	en, err := netaddr.ParseEntry(entry)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := en.String()
	prevAllow, hadAllow := s.state.Allowlist[key]
	snapshot := s.snapshotLocked()

	s.state.Allowlist[key] = AllowEntry{IP: key, AddedAt: s.now(), Note: note}
	var removed []Ban
	for k, b := range s.state.Bans {
		a, err := netaddr.Parse(k)
		if err == nil && en.Contains(a) {
			removed = append(removed, b)
			delete(s.state.Bans, k)
			s.state.Releases[k] = Release{IP: k, Since: s.now(), Reason: "allowlisted"}
		}
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i].IP < removed[j].IP })
	if err := s.saveStateLocked(); err != nil {
		s.restoreLocked(snapshot)
		if hadAllow {
			s.state.Allowlist[key] = prevAllow
		}
		return "", nil, err
	}
	return key, removed, nil
}

// IsAllowed reports whether the address is allowlisted, as an address or
// inside an allowlisted network. Any spelling of the address matches.
func (s *Store) IsAllowed(ip string) bool {
	a, err := netaddr.Parse(ip)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowedLocked(a)
}

func (s *Store) allowedLocked(a netip.Addr) bool {
	if _, ok := s.state.Allowlist[a.String()]; ok {
		return true
	}
	for k := range s.state.Allowlist {
		if en, err := netaddr.ParseEntry(k); err == nil && en.IsNetwork() && en.Contains(a) {
			return true
		}
	}
	return false
}

// Unallow removes an entry from the allowlist, reporting whether it was there.
func (s *Store) Unallow(entry string) (bool, error) {
	en, err := netaddr.ParseEntry(entry)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := en.String()
	prev, ok := s.state.Allowlist[key]
	if !ok {
		return false, nil
	}
	delete(s.state.Allowlist, key)
	if err := s.saveStateLocked(); err != nil {
		s.state.Allowlist[key] = prev
		return false, err
	}
	return true, nil
}

// Allowlist returns the allowlist, sorted by entry.
func (s *Store) Allowlist() []AllowEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AllowEntry, 0, len(s.state.Allowlist))
	for _, e := range s.state.Allowlist {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// RecordBan stores a ban decision, incrementing the repeat counter for an
// address that has been banned before.
func (s *Store) RecordBan(ip, reason string, until time.Time) (Ban, error) {
	a, err := netaddr.Parse(ip)
	if err != nil {
		return Ban{}, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recordBanLocked(a.String(), reason, until, "", false)
}

// BanOptions say who asked and whether the decision owes a notification.
type BanOptions struct {
	Origin    string
	NoticeDue bool
}

// EnsureBan creates a decision only when there is no active ban. Repeated
// requests retain the original duration, reason and repeat count. The check
// and persistence share the store lock, including across different callers.
func (s *Store) EnsureBan(ip, reason string, until time.Time) (Ban, bool, error) {
	return s.EnsureBanWith(ip, reason, until, BanOptions{})
}

// EnsureBanWith is EnsureBan with the origin and the notification duty
// recorded in the same write as the decision.
func (s *Store) EnsureBanWith(ip, reason string, until time.Time, o BanOptions) (Ban, bool, error) {
	a, err := netaddr.Parse(ip)
	if err != nil {
		return Ban{}, false, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	key := a.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.allowedLocked(a) {
		return Ban{}, false, ErrAllowlisted
	}
	if b, ok := s.state.Bans[key]; ok && b.Active(s.now()) {
		return b, false, nil
	}
	b, err := s.recordBanLocked(key, reason, until, o.Origin, o.NoticeDue)
	return b, err == nil, err
}

func (s *Store) recordBanLocked(key, reason string, until time.Time, origin string, notice bool) (Ban, error) {
	a, _ := netaddr.Parse(key)
	if s.allowedLocked(a) {
		return Ban{}, ErrAllowlisted
	}
	snapshot := s.snapshotLocked()
	b := s.state.Bans[key]
	b.IP = key
	b.CreatedAt = s.now()
	b.Until = until
	b.Reason = reason
	b.Count++
	b.State, b.Applied = StatePending, false
	b.LastError, b.Attempts = "", 0
	b.VerifiedAt = time.Time{}
	b.Origin = origin
	b.NoticeDue = notice
	s.state.Bans[key] = b
	// A new decision supersedes a pending release of the same address.
	delete(s.state.Releases, key)
	if err := s.saveStateLocked(); err != nil {
		s.restoreLocked(snapshot)
		return Ban{}, err
	}
	return b, nil
}

// UpdateBan changes the enforcement fields of a ban atomically. fn must not
// change identity fields; it is not called when there is no such ban.
func (s *Store) UpdateBan(ip string, fn func(*Ban)) (Ban, bool, error) {
	a, err := netaddr.Parse(ip)
	if err != nil {
		return Ban{}, false, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	key := a.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.state.Bans[key]
	if !ok {
		return Ban{}, false, nil
	}
	prev := b
	fn(&b)
	b.IP = key
	b = normalizeBan(b)
	if b == prev {
		return b, true, nil
	}
	s.state.Bans[key] = b
	if err := s.saveStateLocked(); err != nil {
		s.state.Bans[key] = prev
		return prev, true, err
	}
	return b, true, nil
}

// MarkBanApplied records that a Banner enforced the decision on the host.
func (s *Store) MarkBanApplied(ip string) error {
	now := s.now()
	_, _, err := s.UpdateBan(ip, func(b *Ban) {
		b.State, b.VerifiedAt, b.LastError = StateApplied, now, ""
	})
	return err
}

// MarkBanUnapplied clears a confirmation that no longer holds.
func (s *Store) MarkBanUnapplied(ip string) error {
	_, _, err := s.UpdateBan(ip, func(b *Ban) {
		if b.State == StateApplied {
			b.State = StatePending
		}
	})
	return err
}

// Bans returns every recorded ban, newest first.
func (s *Store) Bans() []Ban {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Ban, 0, len(s.state.Bans))
	for _, b := range s.state.Bans {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Ban returns one record.
func (s *Store) Ban(ip string) (Ban, bool) {
	a, err := netaddr.Parse(ip)
	if err != nil {
		return Ban{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.state.Bans[a.String()]
	return b, ok
}

// Unban removes a ban decision, reporting whether it existed. The removal and
// the duty to lift the block in the firewall are written together: a crash
// leaves a Release behind, never a silent block.
func (s *Store) Unban(ip string) (bool, error) {
	a, err := netaddr.Parse(ip)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	key := a.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Bans[key]; !ok {
		return false, nil
	}
	snapshot := s.snapshotLocked()
	delete(s.state.Bans, key)
	s.state.Releases[key] = Release{IP: key, Since: s.now(), Reason: "unban"}
	if err := s.saveStateLocked(); err != nil {
		s.restoreLocked(snapshot)
		return false, err
	}
	return true, nil
}

// Releases returns the blocks that still have to be lifted, oldest first.
func (s *Store) Releases() []Release {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Release, 0, len(s.state.Releases))
	for _, r := range s.state.Releases {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since.Before(out[j].Since) })
	return out
}

// UpdateRelease records an attempt to lift a block. A nil error clears it.
func (s *Store) UpdateRelease(ip string, attemptErr error) error {
	a, err := netaddr.Parse(ip)
	if err != nil {
		return nil
	}
	key := a.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.state.Releases[key]
	if !ok {
		return nil
	}
	snapshot := s.snapshotLocked()
	if attemptErr == nil {
		delete(s.state.Releases, key)
	} else {
		r.Attempts++
		r.LastError = attemptErr.Error()
		if len(r.LastError) > 200 {
			r.LastError = r.LastError[:200]
		}
		s.state.Releases[key] = r
	}
	if err := s.saveStateLocked(); err != nil {
		s.restoreLocked(snapshot)
		return err
	}
	return nil
}

// ClearNotice records that the notification of a ban is in the outbox.
func (s *Store) ClearNotice(ip string) error {
	_, _, err := s.UpdateBan(ip, func(b *Ban) { b.NoticeDue = false })
	return err
}

// snapshotLocked copies the maps that a failed save must put back.
func (s *Store) snapshotLocked() persisted {
	p := s.state
	p.Allowlist = make(map[string]AllowEntry, len(s.state.Allowlist))
	for k, v := range s.state.Allowlist {
		p.Allowlist[k] = v
	}
	p.Bans = make(map[string]Ban, len(s.state.Bans))
	for k, v := range s.state.Bans {
		p.Bans[k] = v
	}
	p.Releases = make(map[string]Release, len(s.state.Releases))
	for k, v := range s.state.Releases {
		p.Releases[k] = v
	}
	return p
}

func (s *Store) restoreLocked(p persisted) {
	s.state.Allowlist, s.state.Bans, s.state.Releases = p.Allowlist, p.Bans, p.Releases
}

// writeFileAtomic replaces path so that a crash leaves the old content or the
// new, never a mixture: temporary file, fsync, rename, fsync of the directory.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil && !errors.Is(err, os.ErrPermission) {
		_ = err // best effort on filesystems without modes
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
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
