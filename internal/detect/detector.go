// Package detect turns a stream of events into ban decisions. v0.1 ships the
// interface only; the sliding-window brute-force detector arrives in v0.2.
//
// The shape is intentionally simple: a detector sees every event in order and
// returns the decisions that event triggered. That keeps the detector testable
// without a clock of its own and lets several detectors run side by side.
package detect

import (
	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/model"
)

// Result is what one event triggered: addresses to block, and events the
// detector itself produced (a success after a burst of failures is not in the
// audit log as such — it only exists as a pattern across records).
type Result struct {
	Decisions []action.Decision
	Events    []model.Event
}

// Empty reports whether nothing was triggered.
func (r Result) Empty() bool { return len(r.Decisions) == 0 && len(r.Events) == 0 }

// Detector consumes events and emits decisions and derived events.
type Detector interface {
	// Feed reports what one event triggered. The event's own timestamp is the
	// clock, so replaying a log produces exactly the same result as watching
	// it live.
	Feed(ev model.Event) Result
	// Name identifies the detector in logs and in /status.
	Name() string
}
