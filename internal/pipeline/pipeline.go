// Package pipeline wires the stages together: follow the audit log, assemble
// records into events, translate them, store them and alert on them. It also
// runs the two background duties that keep the agent honest — the heartbeat
// that notices auditd going quiet, and the retention purge.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/parse"
	"github.com/RsNest/auditdsec/internal/semantic"
	"github.com/RsNest/auditdsec/internal/source"
	"github.com/RsNest/auditdsec/internal/store"
)

// Notifier is the alerting side of the pipeline, implemented by the Telegram
// client. Keeping it an interface means tests need no network and a second
// channel (ntfy, a webhook) can be added without touching this package.
type Notifier interface {
	Notify(ctx context.Context, ev model.Event) error
}

// lineBuffer is how many log lines may wait to be processed. When it fills the
// tailer blocks, which is the right trade: slowing down beats losing events.
const lineBuffer = 2048

// Options configures the pipeline.
type Options struct {
	AuditLog      string
	StateDir      string
	Host          string
	ReadFromStart bool

	// HeartbeatEvery is how often the audit log is checked, and
	// HeartbeatStale how old its last write may get before that counts as
	// "auditd has gone quiet". Zero StaleAfter checks readability only.
	HeartbeatEnabled bool
	HeartbeatEvery   time.Duration
	HeartbeatStale   time.Duration

	// PurgeEvery is how often old event files are deleted.
	PurgeEvery time.Duration

	Store    *store.Store
	Notifier Notifier
	Logger   *slog.Logger
	Now      func() time.Time
}

// Pipeline is the running agent.
type Pipeline struct {
	opt Options
	log *slog.Logger
	now func() time.Time

	mapper *semantic.Mapper
	asm    *parse.Assembler

	processed atomic.Uint64
	reported  atomic.Uint64
	skipped   atomic.Uint64

	heartbeatFiring bool
	heartbeatAt     time.Time
}

// New validates the options and returns a pipeline.
func New(o Options) (*Pipeline, error) {
	if o.AuditLog == "" {
		return nil, fmt.Errorf("pipeline: AuditLog is required")
	}
	if o.Store == nil {
		return nil, fmt.Errorf("pipeline: Store is required")
	}
	if o.Notifier == nil {
		return nil, fmt.Errorf("pipeline: Notifier is required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.HeartbeatEvery <= 0 {
		o.HeartbeatEvery = time.Minute
	}
	if o.PurgeEvery <= 0 {
		o.PurgeEvery = time.Hour
	}
	return &Pipeline{
		opt:    o,
		log:    o.Logger,
		now:    o.Now,
		mapper: semantic.New(o.Host),
		asm:    parse.NewAssembler(2 * time.Second),
	}, nil
}

// Run follows the log until the context is cancelled.
func (p *Pipeline) Run(ctx context.Context) error {
	statePath := ""
	if p.opt.StateDir != "" {
		statePath = filepath.Join(p.opt.StateDir, "tail.json")
	}
	tailer := source.New(source.Options{
		Path:      p.opt.AuditLog,
		StatePath: statePath,
		FromStart: p.opt.ReadFromStart,
		Logger:    p.log,
	})

	lines := make(chan string, lineBuffer)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(lines)
		if err := tailer.Run(ctx, func(l string) {
			select {
			case lines <- l:
			case <-ctx.Done():
			}
		}); err != nil {
			p.log.Error("the log reader stopped", "error", err)
		}
	}()

	expire := time.NewTicker(time.Second)
	defer expire.Stop()
	heartbeat := time.NewTicker(p.opt.HeartbeatEvery)
	defer heartbeat.Stop()
	purge := time.NewTicker(p.opt.PurgeEvery)
	defer purge.Stop()

	p.log.Info("watching the audit log",
		"path", p.opt.AuditLog, "host", p.opt.Host, "from_start", p.opt.ReadFromStart)
	p.purgeOldEvents()

	for {
		select {
		case <-ctx.Done():
			p.emit(context.WithoutCancel(ctx), p.asm.Flush())
			wg.Wait()
			p.log.Info("stopped",
				"events", p.processed.Load(), "alerts", p.reported.Load(), "skipped_lines", p.skipped.Load())
			return nil

		case line, ok := <-lines:
			if !ok {
				wg.Wait()
				return nil
			}
			p.feed(ctx, line)

		case <-expire.C:
			p.emit(ctx, p.asm.Expire(p.now()))

		case <-heartbeat.C:
			p.checkHeartbeat(ctx)

		case <-purge.C:
			p.purgeOldEvents()
		}
	}
}

// feed pushes one log line through the assembler and emits whatever it closed.
func (p *Pipeline) feed(ctx context.Context, line string) {
	events, err := p.asm.Add(line, p.now())
	if err != nil {
		p.skipped.Add(1)
		p.log.Debug("line skipped", "error", err)
	}
	p.emit(ctx, events)
}

// emit translates assembled events, stores the interesting ones and alerts.
func (p *Pipeline) emit(ctx context.Context, events []*parse.Event) {
	for _, ae := range events {
		ev, ok := p.mapper.Map(ae)
		if !ok {
			continue
		}
		p.processed.Add(1)
		p.deliver(ctx, ev)
	}
}

func (p *Pipeline) deliver(ctx context.Context, ev model.Event) {
	if err := p.opt.Store.AppendEvent(ev); err != nil {
		p.log.Error("cannot store the event", "kind", ev.Kind, "error", err)
	}
	if err := p.opt.Notifier.Notify(ctx, ev); err != nil {
		p.log.Error("cannot send the alert", "kind", ev.Kind, "error", err)
		return
	}
	p.reported.Add(1)
	p.log.Debug("event handled",
		"kind", ev.Kind, "severity", ev.Severity.String(), "user", ev.User, "ip", ev.SrcIP)
}

// checkHeartbeat reports the audit log going unreadable or silent. Silence is
// the failure mode that matters: an attacker who stops auditd leaves no events
// behind, and without this check the agent would simply look calm.
func (p *Pipeline) checkHeartbeat(ctx context.Context) {
	if !p.opt.HeartbeatEnabled {
		return
	}
	now := p.now()
	reason := ""

	fi, err := os.Stat(p.opt.AuditLog)
	switch {
	case err != nil:
		reason = fmt.Sprintf("%s: %v", p.opt.AuditLog, err)
	case p.opt.HeartbeatStale > 0 && now.Sub(fi.ModTime()) > p.opt.HeartbeatStale:
		reason = fmt.Sprintf("%s: no new records for %s", p.opt.AuditLog, now.Sub(fi.ModTime()).Round(time.Minute))
	}

	if reason == "" {
		if p.heartbeatFiring {
			p.heartbeatFiring = false
			p.log.Info("the audit log is being written again", "path", p.opt.AuditLog)
		}
		return
	}

	cooldown := p.opt.HeartbeatStale
	if cooldown < time.Hour {
		cooldown = time.Hour
	}
	if p.heartbeatFiring && now.Sub(p.heartbeatAt) < cooldown {
		return
	}
	p.heartbeatFiring, p.heartbeatAt = true, now
	p.log.Warn("the audit log is not alive", "reason", reason)

	ev := semantic.HeartbeatLost(p.opt.Host, reason)
	ev.Time = now
	p.deliver(ctx, ev)
}

func (p *Pipeline) purgeOldEvents() {
	removed, err := p.opt.Store.Purge()
	if err != nil {
		p.log.Error("cannot purge old events", "error", err)
		return
	}
	if removed > 0 {
		p.log.Info("old event files removed", "files", removed)
	}
}

// Counters reports what the pipeline has done, for diagnostics.
func (p *Pipeline) Counters() (processed, reported, skipped uint64) {
	return p.processed.Load(), p.reported.Load(), p.skipped.Load()
}
