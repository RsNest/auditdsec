// Package auditlog answers one question: can the agent see what auditd writes?
// "Cannot read the log" and "the log is quiet" are different failures with
// different causes, so they are reported as different states. Neither is proof
// that auditd stopped: only the first proves the agent is blind.
package auditlog

import (
	"fmt"
	"os"
	"time"
)

// State is the health of the audit log as the agent can observe it.
type State string

const (
	// OK: the log is readable and was written recently enough.
	OK State = "ok"
	// Unavailable: the log is missing, not a regular file or not readable. The
	// agent sees nothing, whatever auditd is doing.
	Unavailable State = "audit_unavailable"
	// Silent: the log is readable but has not been written for longer than the
	// configured limit. A quiet host looks the same as a stopped auditd.
	Silent State = "audit_silent"
)

// Status is one observation.
type Status struct {
	State     State
	Detail    string // human-readable, safe to show
	LastWrite time.Time
}

// Check observes the log at path. A stale limit of zero disables the silence
// test (an unreadable log is still reported).
func Check(path string, now time.Time, stale time.Duration) Status {
	fi, err := os.Stat(path)
	if err != nil {
		return Status{State: Unavailable, Detail: fmt.Sprintf("%s: %v", path, err)}
	}
	if !fi.Mode().IsRegular() {
		return Status{State: Unavailable, Detail: fmt.Sprintf("%s: not a regular file", path), LastWrite: fi.ModTime()}
	}
	f, err := os.Open(path)
	if err != nil {
		return Status{State: Unavailable, Detail: fmt.Sprintf("%s: %v", path, err), LastWrite: fi.ModTime()}
	}
	_ = f.Close()
	if age := now.Sub(fi.ModTime()); stale > 0 && age > stale {
		return Status{
			State:     Silent,
			Detail:    fmt.Sprintf("%s: no new records for %s (a quiet host looks the same as a stopped auditd)", path, age.Round(time.Minute)),
			LastWrite: fi.ModTime(),
		}
	}
	return Status{State: OK, LastWrite: fi.ModTime()}
}
