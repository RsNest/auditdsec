package delivery

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

type bucket struct {
	rate             int
	at               time.Time
	shared, reserved float64
	cooldown         time.Time
}

// Run uses independent routine and critical workers. Provider calls never hold
// the queue lock. Cancellation leaves unconfirmed jobs durable for the next run.
func (q *Queue) Run(ctx context.Context, sender Sender) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	rates := map[string]*bucket{}
	for _, priority := range []Priority{Routine, Critical} {
		wg.Add(1)
		go func(priority Priority) {
			defer wg.Done()
			if err := q.worker(ctx, sender, priority, rates); err != nil {
				errs <- err
				cancel()
			}
		}(priority)
	}
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

func groupKey(in Intent) string {
	return ID(in.Channel, in.Route, in.Destination, string(in.Priority), strconv.Itoa(in.Severity), in.DedupKey)
}

func (q *Queue) flushGroups(now time.Time) error {
	for key, g := range q.s.Groups {
		if now.Before(g.Due) {
			continue
		}
		tx := transaction{Groups: map[string]*group{key: nil}, Sequence: q.s.Sequence}
		if g.Extra > 0 {
			in := g.Last
			in.ID = ID(in.ID, "summary", g.Due.Format(time.RFC3339Nano))
			in.Created = now
			in.GroupedCount = g.Extra
			in.DedupKey = ""
			limit, bytes := q.opt.MaxJobs, q.opt.MaxBytes
			if in.Priority == Routine {
				limit -= q.opt.CriticalJobs
				bytes -= q.opt.CriticalBytes
			}
			if len(q.s.Jobs) >= limit || q.payloadBytes() > bytes {
				if in.Priority == Critical {
					continue
				}
				tx.Stats.Overflow++
			} else {
				tx.Sequence++
				tx.Stats.Queued++
				tx.Upsert = []Job{{Intent: in, Sequence: tx.Sequence, NextAttempt: now}}
			}
		}
		if err := q.commit(tx); err != nil {
			return err
		}
	}
	return nil
}

// Called under q.mu; the rate budget is shared across both workers and all
// recipients of a bot route. Routine traffic cannot consume the critical share.
func admit(rates map[string]*bucket, in Intent, rate int, now time.Time) time.Duration {
	if rate < 1 {
		rate = 1
	}
	key := in.Channel + ":" + in.Route
	b := rates[key]
	reservedRate := math.Max(.2*float64(rate), .2)
	sharedRate := float64(rate) - reservedRate
	sharedCap, reservedCap := math.Max(1, sharedRate), math.Max(1, reservedRate)
	if b == nil || b.rate != rate {
		b = &bucket{rate: rate, at: now, shared: sharedCap, reserved: reservedCap}
		rates[key] = b
	}
	elapsed := math.Max(0, now.Sub(b.at).Seconds())
	b.shared = math.Min(sharedCap, b.shared+elapsed*sharedRate/60)
	b.reserved = math.Min(reservedCap, b.reserved+elapsed*reservedRate/60)
	b.at = now
	if now.Before(b.cooldown) {
		return b.cooldown.Sub(now)
	}
	if in.Priority == Critical && b.reserved >= 1 {
		b.reserved--
		return 0
	}
	if b.shared >= 1 {
		b.shared--
		return 0
	}
	wait := (1 - b.shared) * 60 / sharedRate
	if in.Priority == Critical {
		wait = math.Min(wait, (1-b.reserved)*60/reservedRate)
	}
	return time.Duration(wait*float64(time.Second)) + time.Millisecond
}

func (q *Queue) worker(ctx context.Context, sender Sender, priority Priority, rates map[string]*bucket) error {
	for ctx.Err() == nil {
		q.mu.Lock()
		if q.err != nil {
			err := q.err
			q.mu.Unlock()
			return err
		}
		now := q.opt.Now()
		if err := q.flushGroups(now); err != nil {
			q.mu.Unlock()
			return err
		}
		var candidate Job
		for _, j := range q.s.Jobs {
			if j.Priority != priority || q.inflight[j.ID] || j.NextAttempt.After(now) {
				continue
			}
			if candidate.ID == "" || j.Sequence < candidate.Sequence {
				candidate = j
			}
		}
		if candidate.ID == "" {
			q.mu.Unlock()
			if !q.Wait(ctx.Done()) {
				return nil
			}
			continue
		}
		q.inflight[candidate.ID] = true
		q.mu.Unlock()
		policy := sender.DeliveryPolicy(candidate.Intent)
		q.mu.Lock()
		tx := transaction{}
		if policy.CancelReason != "" || now.Sub(candidate.Created) > 7*24*time.Hour {
			tx.Remove = []string{candidate.ID}
			if policy.CancelReason != "" {
				tx.Stats.Cancelled++
			} else {
				tx.Stats.Failed++
				tx.Failure = &Failure{ID: candidate.ID, Destination: candidate.Destination, At: now, Reason: "expired", Attempts: candidate.Attempts}
			}
		} else if candidate.DedupKey != "" {
			key := groupKey(candidate.Intent)
			if g, ok := q.s.Groups[key]; ok && now.Before(g.Due) {
				g.Extra++
				g.Last = candidate.Intent
				tx.Remove = []string{candidate.ID}
				tx.Stats.Grouped++
				tx.Groups = map[string]*group{key: &g}
			}
		}
		if len(tx.Remove) > 0 {
			err := q.commit(tx)
			q.mu.Unlock()
			if err != nil {
				return err
			}
			continue
		}
		wait := admit(rates, candidate.Intent, policy.RatePerMinute, now)
		if wait > 0 {
			candidate.NextAttempt = now.Add(wait)
			tx.Upsert = []Job{candidate}
			tx.Stats.Deferred++
			err := q.commit(tx)
			delete(q.inflight, candidate.ID)
			q.mu.Unlock()
			if err != nil {
				return err
			}
			continue
		}
		// Persist the attempt before the external side effect. An ambiguous crash
		// may resend it; Telegram supplies no idempotency key for sendMessage.
		candidate.Attempts++
		candidate.NextAttempt = now.Add(30 * time.Second)
		err := q.commit(transaction{Upsert: []Job{candidate}})
		q.mu.Unlock()
		if err != nil {
			return err
		}
		sendctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = sender.SendDelivery(sendctx, candidate.Intent)
		cancel()
		q.mu.Lock()
		delete(q.inflight, candidate.ID)
		if ctx.Err() != nil {
			q.mu.Unlock()
			return nil
		}
		tx = transaction{}
		now = q.opt.Now()
		if err == nil {
			tx.Remove = []string{candidate.ID}
			tx.Stats.Delivered++
			if candidate.DedupKey != "" && candidate.DedupWindow > 0 && len(q.s.Groups) < 512 {
				key := groupKey(candidate.Intent)
				g := group{Last: candidate.Intent, Due: now.Add(candidate.DedupWindow)}
				tx.Groups = map[string]*group{key: &g}
			}
		} else {
			code := "transport_failed"
			var se *SendError
			if errors.As(err, &se) {
				// Adapters return labels only; keep arbitrary error text out of WAL.
				if len(se.Code) <= 128 && !strings.ContainsAny(se.Code, " /:?\r\n") {
					code = se.Code
				}
			}
			if se != nil && se.Cancelled {
				tx.Remove = []string{candidate.ID}
				tx.Stats.Cancelled++
			} else if se != nil && se.Permanent {
				tx.Remove = []string{candidate.ID}
				tx.Stats.Failed++
				tx.Failure = &Failure{ID: candidate.ID, Destination: candidate.Destination, At: now, Reason: code, Attempts: candidate.Attempts}
			} else {
				wait := time.Second * time.Duration(1<<min(candidate.Attempts, 9))
				if se != nil && se.RetryAfter > wait {
					wait = se.RetryAfter
				}
				if wait > 24*time.Hour {
					wait = 24 * time.Hour
				}
				// Stable jitter spreads retries across recipients without a PRNG.
				n, _ := strconv.ParseUint(candidate.ID[:min(8, len(candidate.ID))], 16, 32)
				wait += time.Duration(n%1000) * time.Millisecond
				candidate.NextAttempt = now.Add(wait)
				candidate.LastError = code
				tx.Upsert = []Job{candidate}
				tx.Stats.Retries++
				if se != nil && se.RetryAfter > 0 {
					rates[candidate.Channel+":"+candidate.Route].cooldown = now.Add(wait)
				}
			}
		}
		if err := q.commit(tx); err != nil {
			q.mu.Unlock()
			return fmt.Errorf("persist delivery result: %w", err)
		}
		// Bound temporary rate state as credentials are rotated. Durable retry
		// deadlines survive even when an inactive fingerprint is discarded.
		if len(rates) > q.opt.MaxJobs {
			clear(rates)
		}
		q.mu.Unlock()
	}
	return nil
}
