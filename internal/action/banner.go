// Package action applies decisions on the host. v0.1 ships the interface and a
// no-op implementation: ban decisions are recorded in the store and shown in
// Telegram, but nothing on the host is touched yet.
//
// v0.2 adds a Banner backed by nftables or ipset, and v0.3 one backed by the
// CrowdSec local API, so that a CrowdSec bouncer enforces the decision instead
// of the agent needing NET_ADMIN of its own.
package action

import (
	"context"
	"time"
)

// Decision is "this address should be blocked until this moment". A zero Until
// means permanently.
type Decision struct {
	IP     string
	Until  time.Time
	Reason string
}

// Permanent reports whether the decision has no expiry.
func (d Decision) Permanent() bool { return d.Until.IsZero() }

// Banner enforces ban decisions on the host.
type Banner interface {
	// Ban blocks an address. Implementations must be idempotent: the same
	// decision may arrive twice after a restart.
	Ban(ctx context.Context, d Decision) error
	// Unban removes a block, and succeeds when there was nothing to remove.
	Unban(ctx context.Context, ip string) error
	// List returns the blocks currently in force.
	List(ctx context.Context) ([]Decision, error)
	// Name identifies the implementation in logs and in /status.
	Name() string
}

// NoopBanner records nothing and blocks nothing. It keeps the pipeline honest
// in v0.1: the decision is visible to the user, and the user is told plainly
// that enforcement is not wired up yet.
type NoopBanner struct{}

func (NoopBanner) Ban(context.Context, Decision) error      { return nil }
func (NoopBanner) Unban(context.Context, string) error      { return nil }
func (NoopBanner) List(context.Context) ([]Decision, error) { return nil, nil }
func (NoopBanner) Name() string                             { return "noop" }
