// Package delivery implements a bounded, durable notification outbox. It has
// no channel credentials: adapters prepare payloads and validate routes at send time.
package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

type Priority string

const (
	Routine  Priority = "routine"
	Critical Priority = "critical"
)

// Intent is an immutable message for one recipient. Route is a credential
// fingerprint, never a token. Payload contains only the channel request body.
type Intent struct {
	ID           string          `json:"id"`
	Channel      string          `json:"channel"`
	Route        string          `json:"route"`
	Destination  string          `json:"destination"`
	Category     string          `json:"category"`
	Severity     int             `json:"severity"`
	Priority     Priority        `json:"priority"`
	Created      time.Time       `json:"created"`
	Payload      json.RawMessage `json:"payload"`
	DedupKey     string          `json:"dedup_key,omitempty"`
	DedupWindow  time.Duration   `json:"dedup_window,omitempty"`
	GroupSummary string          `json:"group_summary,omitempty"`
	GroupedCount int             `json:"grouped_count,omitempty"`
}

// Plan is stored in the same journal record as its event. A suppressed event
// still records the policy decision, without pretending that a message was sent.
type Plan struct {
	Intents    []Intent `json:"intents,omitempty"`
	Suppressed string   `json:"suppressed,omitempty"`
}

type Position struct {
	Day   string `json:"day"`
	Start int64  `json:"start"`
	End   int64  `json:"end"`
}

type Job struct {
	Intent
	Sequence    uint64    `json:"sequence"`
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"next_attempt"`
	LastError   string    `json:"last_error,omitempty"`
}

type Failure struct {
	ID          string    `json:"id"`
	Destination string    `json:"destination"`
	At          time.Time `json:"at"`
	Reason      string    `json:"reason"`
	Attempts    int       `json:"attempts"`
}

type Stats struct {
	Queued       uint64 `json:"queued"`
	Delivered    uint64 `json:"delivered"`
	Suppressed   uint64 `json:"suppressed"`
	Grouped      uint64 `json:"grouped"`
	Deferred     uint64 `json:"deferred"`
	Retries      uint64 `json:"retries"`
	Failed       uint64 `json:"failed"`
	Cancelled    uint64 `json:"cancelled"`
	Overflow     uint64 `json:"overflow"`
	Pending      int    `json:"pending"`
	Critical     int    `json:"critical_pending"`
	InFlight     int    `json:"in_flight"`
	PayloadBytes int    `json:"payload_bytes"`
}

// Policy is evaluated again before delivery, so removed recipients and changed
// credentials never receive queued messages under a different route.
type Policy struct {
	CancelReason  string
	RatePerMinute int
}

type Sender interface {
	DeliveryPolicy(Intent) Policy
	SendDelivery(context.Context, Intent) error
}

// SendError distinguishes permanent provider rejection from a retryable outage.
// Code must be a safe diagnostic label, not a URL, token or provider payload.
type SendError struct {
	Code       string
	Permanent  bool
	RetryAfter time.Duration
}

func (e *SendError) Error() string { return e.Code }

func ID(parts ...string) string {
	raw, _ := json.Marshal(parts)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
