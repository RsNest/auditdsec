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

// Detector consumes events and emits ban decisions.
type Detector interface {
	// Feed reports the decisions triggered by one event. The event's own
	// timestamp is the clock, so replaying a log produces the same result.
	Feed(ev model.Event) []action.Decision
	// Name identifies the detector in logs and in /status.
	Name() string
}

// Escalation is the ban ladder a repeat offender climbs: the first offence
// costs an hour, the next a day, then a month, and only a persistent attacker
// is banned permanently. Starting at "forever" would lock out owners on
// dynamic addresses, which is why the ladder exists at all.
//
// The values are indexed by how many times the address has been banned before.
var Escalation = []string{"1h", "24h", "720h", "permanent"}
