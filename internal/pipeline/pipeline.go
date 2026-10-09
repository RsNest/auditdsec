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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/parse"
	"github.com/RsNest/auditdsec/internal/redact"
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

	// Debug logs every line read and the reason every record was dropped, and
	// prints the counters periodically. It answers the question debugging this
	// agent actually raises: why did no alert arrive for something I just did.
	Debug bool

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
	tailer *source.Tailer

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
	statePath := ""
	if o.StateDir != "" {
		statePath = filepath.Join(o.StateDir, "tail.json")
	}
	return &Pipeline{
		opt:    o,
		log:    o.Logger,
		now:    o.Now,
		mapper: semantic.New(o.Host),
		asm:    parse.NewAssembler(2 * time.Second),
		tailer: source.New(source.Options{
			Path:      o.AuditLog,
			StatePath: statePath,
			FromStart: o.ReadFromStart,
			Logger:    o.Logger,
		}),
	}, nil
}

// Run follows the log until the context is cancelled.
func (p *Pipeline) Run(ctx context.Context) error {
	lines := make(chan string, lineBuffer)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(lines)
		if err := p.tailer.Run(ctx, func(l string) {
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

	// In debug mode the counters are printed regularly, so a quiet agent can be
	// told apart from a stuck one.
	counters := newOptionalTicker(p.opt.Debug, 30*time.Second)
	defer counters.Stop()

	p.log.Info("watching the audit log",
		"path", p.opt.AuditLog, "host", p.opt.Host,
		"from_start", p.opt.ReadFromStart, "debug", p.opt.Debug)
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

		case <-counters.C:
			processed, reported, skipped := p.Counters()
			p.log.Debug("counters",
				"events", processed, "alerts", reported, "skipped_lines", skipped,
				"open_audit_events", p.asm.Pending())
		}
	}
}

// feed pushes one log line through the assembler and emits whatever it closed.
func (p *Pipeline) feed(ctx context.Context, line string) {
	if p.opt.Debug {
		// Secrets are masked first: a debug log is still a file on disk, and a
		// hex-encoded sudo command would otherwise carry a password into it.
		p.log.Debug("audit line", "line", redact.AuditLine(line))
	}
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
		ev, reason, ok := p.mapper.MapVerbose(ae)
		if !ok {
			p.log.Debug("audit event ignored",
				"types", strings.Join(ae.Types(), ","),
				"serial", ae.Serial,
				"keys", strings.Join(ae.AuditKeys(), ","),
				"reason", reason)
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

// DiagItem is one line of the /debug report: an i18n key for the label, and the
// value to show beside it.
type DiagItem struct {
	Key   string
	Value string
}

// Diagnostics is what only the pipeline knows, for the /debug command.
func (p *Pipeline) Diagnostics() []DiagItem {
	processed, reported, skipped := p.Counters()

	auditLog := "ok"
	if fi, err := os.Stat(p.opt.AuditLog); err != nil {
		auditLog = err.Error()
	} else {
		auditLog = fmt.Sprintf("ok, %d bytes, written %s ago",
			fi.Size(), p.now().Sub(fi.ModTime()).Round(time.Second))
	}

	return []DiagItem{
		{Key: "ui.diag.events", Value: strconv.FormatUint(processed, 10)},
		{Key: "ui.diag.alerts", Value: strconv.FormatUint(reported, 10)},
		{Key: "ui.diag.skipped", Value: strconv.FormatUint(skipped, 10)},
		{Key: "ui.diag.audit_log", Value: auditLog},
		{Key: "ui.diag.offset", Value: strconv.FormatInt(p.tailer.LastOffset(), 10)},
	}
}

// optionalTicker is a ticker that can be switched off, so a select can always
// read from its channel.
type optionalTicker struct {
	C  <-chan time.Time
	t  *time.Ticker
	on bool
}

func newOptionalTicker(on bool, d time.Duration) optionalTicker {
	if !on {
		return optionalTicker{C: nil}
	}
	t := time.NewTicker(d)
	return optionalTicker{C: t.C, t: t, on: true}
}

func (o optionalTicker) Stop() {
	if o.on {
		o.t.Stop()
	}
}
