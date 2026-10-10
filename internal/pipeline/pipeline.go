// Package pipeline wires the stages together: follow the audit log, assemble
// records into events, translate them, store them and alert on them. It also
// runs the two background duties that keep the agent honest — the heartbeat
// that notices auditd going quiet, and the retention purge.
package pipeline

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/detect"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/netcheck"
	"github.com/RsNest/auditdsec/internal/parse"
	"github.com/RsNest/auditdsec/internal/redact"
	"github.com/RsNest/auditdsec/internal/semantic"
	"github.com/RsNest/auditdsec/internal/source"
	"github.com/RsNest/auditdsec/internal/store"
)

// Notifier is the alerting side of the pipeline, implemented by the Telegram
// client. Keeping it an interface means tests need no network and a second
// channel (ntfy, a webhook) can be added without touching this package.
// DeliveryPlanner snapshots immutable notification intents without network I/O.
type DeliveryPlanner interface {
	delivery.Sender
	PlanEvent(model.Event) delivery.Plan
	PlanBan(store.Ban, error) delivery.Plan
	PlanMessage(string, map[string]string) delivery.Plan
}

type Notifier interface {
	// Notify reports one event.
	Notify(ctx context.Context, ev model.Event) error
	// NotifyBan reports a ban decision. applyErr is non-nil when the decision
	// was recorded but the firewall refused it, which the owner must know
	// about: a ban that was not applied protects nothing.
	NotifyBan(ctx context.Context, b store.Ban, applyErr error) error
	// NotifyMessage sends a plain localized notice, such as the first address
	// being allowlisted.
	NotifyMessage(ctx context.Context, key string, args map[string]string) error
}

// metaFirstLoginAllowed records that the owner's address has been protected,
// so it happens once per installation rather than on every restart.
const metaFirstLoginAllowed = "first_login_allowlisted"

// lineBuffer is how many log lines may wait to be processed. When it fills the
// tailer blocks, which is the right trade: slowing down beats losing events.
const lineBuffer = 16

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

	// Detector turns events into ban decisions. Nil disables detection.
	Detector detect.Detector
	// Banner applies decisions on the host. Nil, or the no-op banner, means
	// decisions are recorded and reported but nothing is blocked.
	Banner action.Banner
	// AutoAllowlistFirstLogin protects the source of the first successful
	// login after startup, which is almost always the person installing the
	// agent. It is what stops the detector locking its owner out.
	AutoAllowlistFirstLogin bool

	// PanelURL is the panel's public https link. When set, the certificate the
	// proxy actually serves there is checked every PanelCertEvery (default an
	// hour); a certificate close to its end, or one that does not verify when
	// PanelCertTrust is on, is reported. Staging and self-signed setups turn
	// PanelCertTrust off, so only the expiry is watched.
	PanelURL       string
	PanelCertEvery time.Duration
	PanelCertTrust bool

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

	mapper        *semantic.Mapper
	asm           *parse.Assembler
	tailer        *source.Tailer
	current       source.Cursor
	openPositions map[int64]source.Cursor
	fatal         chan error
	planner       DeliveryPlanner
	outbox        *delivery.Queue

	processed atomic.Uint64
	reported  atomic.Uint64
	skipped   atomic.Uint64

	banned          atomic.Uint64
	heartbeatFiring bool
	heartbeatAt     time.Time

	certMu     sync.Mutex
	certStatus string // for diagnostics: "ok, until ...", the problem, or "not checked yet"
	certFiring bool
	certAt     time.Time
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
	if o.PanelCertEvery <= 0 {
		o.PanelCertEvery = time.Hour
	}
	statePath := ""
	if o.StateDir != "" {
		statePath = filepath.Join(o.StateDir, "tail.json")
	}
	p := &Pipeline{
		opt:           o,
		log:           o.Logger,
		now:           o.Now,
		mapper:        semantic.New(o.Host),
		asm:           parse.NewAssembler(2 * time.Second),
		openPositions: map[int64]source.Cursor{},
		fatal:         make(chan error, 1),
		tailer: source.New(source.Options{
			Path:      o.AuditLog,
			StatePath: statePath,
			FromStart: o.ReadFromStart,
			Logger:    o.Logger,
		}),
	}
	if planner, ok := o.Notifier.(DeliveryPlanner); ok {
		if o.StateDir == "" {
			return nil, errors.New("pipeline: StateDir is required for durable delivery")
		}
		q, err := delivery.Open(delivery.Options{Dir: filepath.Join(o.StateDir, "outbox"), Now: o.Now})
		if err != nil {
			return nil, err
		}
		p.planner, p.outbox = planner, q
		if managed, ok := o.Notifier.(interface{ UseOutbox() }); ok {
			managed.UseOutbox()
		}
	}
	return p, nil
}

// Close releases the outbox after Run and its workers have stopped.
func (p *Pipeline) Close() error {
	if p.outbox != nil {
		return p.outbox.Close()
	}
	return nil
}

// Run follows the log until the context is cancelled.
func (p *Pipeline) Run(ctx context.Context) error {
	p.reapplyBans(ctx)
	if p.outbox != nil {
		workerctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := p.outbox.Run(workerctx, p.planner); err != nil {
				p.failDelivery(err)
			}
		}()
		defer func() { cancel(); <-done }()
		if err := p.recoverDeliveries(ctx); err != nil {
			return err
		}
		if startup, ok := p.opt.Notifier.(interface{ PlanStartup() delivery.Plan }); ok {
			if err := p.enqueueNotice(ctx, startup.PlanStartup()); err != nil {
				return err
			}
		}
	}

	lines := make(chan source.Line, lineBuffer)
	tailctx, stopReader := context.WithCancel(ctx)
	readerErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(lines)
		err := p.tailer.RunLines(tailctx, func(l source.Line) error {
			select {
			case lines <- l:
				return nil
			case <-tailctx.Done():
				return tailctx.Err()
			}
		})
		if err != nil {
			p.log.Error("the log reader stopped", "error", err)
		}
		readerErr <- err
	}()
	defer func() { stopReader(); wg.Wait() }()

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
		"from_start", p.opt.ReadFromStart, "debug", p.opt.Debug,
		"detector", detectorName(p.opt.Detector), "banner", bannerName(p.opt.Banner))
	p.purgeOldEvents()

	certs := make(chan certResult, 1)
	if strings.HasPrefix(p.opt.PanelURL, "https://") {
		go p.watchPanelCert(ctx, certs)
	}

	for {
		select {
		case err := <-p.fatal:
			return err
		case <-ctx.Done():
			// Open events and unread queued lines remain behind the saved cursor.
			// Flushing them on shutdown would persist fragments before their EOE.
			p.log.Info("stopped",
				"events", p.processed.Load(), "alerts", p.reported.Load(), "skipped_lines", p.skipped.Load())
			return nil

		case line, ok := <-lines:
			if !ok {
				return <-readerErr
			}
			if err := p.feedSource(ctx, line); err != nil {
				return err
			}

		case <-expire.C:
			if err := p.emit(ctx, p.asm.Expire(p.now())); err != nil {
				return err
			}
			if err := p.acknowledge(); err != nil {
				return err
			}

		case <-heartbeat.C:
			p.checkHeartbeat(ctx)

		case <-purge.C:
			if err := p.recoverDeliveries(ctx); err != nil {
				return err
			}
			p.purgeOldEvents()

		case r := <-certs:
			p.judgePanelCert(ctx, r)

		case <-counters.C:
			processed, reported, skipped := p.Counters()
			p.log.Debug("counters",
				"events", processed, "alerts", reported, "skipped_lines", skipped,
				"open_audit_events", p.asm.Pending())
		}
	}
}

// feed pushes one log line through the assembler and emits whatever it closed.
func (p *Pipeline) feedSource(ctx context.Context, line source.Line) error {
	if line.Boundary {
		if err := p.emit(ctx, p.asm.FlushWithReason(parse.IncompleteSource)); err != nil {
			return err
		}
		p.asm = parse.NewAssembler(2 * time.Second)
		p.openPositions = map[int64]source.Cursor{}
		p.current = line.End
		return p.acknowledge()
	}
	if line.Start.Generation != p.current.Generation {
		return errors.New("pipeline: source generation changed without a boundary")
	}
	p.current = line.End
	if line.Oversized || line.Skipped {
		p.skipped.Add(1)
		p.log.Warn("discarded source line", "start", line.Start.Offset, "end", line.End.Offset, "oversized", line.Oversized)
		return p.acknowledge()
	}
	lineText := line.Text
	if p.opt.Debug {
		// Secrets are masked first: a debug log is still a file on disk, and a
		// hex-encoded sudo command would otherwise carry a password into it.
		p.log.Debug("audit line", "line", redact.AuditLine(lineText))
	}
	events, err := p.asm.AddAt(lineText, line.Start.Offset, p.now())
	if err != nil {
		p.skipped.Add(1)
		p.log.Debug("line skipped", "error", err)
	}
	if err := p.emit(ctx, events); err != nil {
		return err
	}
	for _, start := range p.asm.OpenStarts() {
		if start == line.Start.Offset {
			p.openPositions[start] = line.Start
		}
	}
	return p.acknowledge()
}

func (p *Pipeline) acknowledge() error {
	if p.current.Generation == "" {
		return nil
	}
	positions := map[int64]source.Cursor{}
	for _, start := range p.asm.OpenStarts() {
		c, ok := p.openPositions[start]
		if !ok {
			return errors.New("pipeline: missing cursor for an open audit event")
		}
		positions[start] = c
	}
	p.openPositions = positions
	checkpoint := p.current
	if start, ok := p.asm.OldestOpen(); ok {
		checkpoint = positions[start]
	}
	if err := p.tailer.SaveCursor(checkpoint); err != nil {
		return fmt.Errorf("persist acknowledged source cursor: %w", err)
	}
	return nil
}

// emit translates assembled events, stores the interesting ones and alerts.
func (p *Pipeline) emit(ctx context.Context, events []*parse.Event) error {
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
		if p.current.Generation != "" {
			key := fmt.Sprintf("%q|%q|%q|%d|%d|%d", p.current.Path, p.current.Generation, ae.Node, ae.Time.UnixNano(), ae.Serial, ae.Start)
			ev.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
		}
		if err := p.handle(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

// handle journals an event before detection, and enforces its decisions before
// sending the triggering alert. Derived events are never fed back into detection.
func (p *Pipeline) handle(ctx context.Context, ev model.Event) error {
	added, err := p.persistEvent(ev)
	if err != nil {
		return err
	}
	if !added {
		return nil
	}
	p.autoAllowlist(ctx, ev)

	var res detect.Result
	if p.opt.Detector != nil {
		res = p.opt.Detector.Feed(ev)
	}
	for _, d := range res.Decisions {
		p.applyDecision(ctx, d)
	}
	if err := p.notifyEvent(ctx, ev); err != nil {
		return err
	}
	for n, derived := range res.Events {
		if ev.ID != "" {
			derived.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", ev.ID, derived.Kind, n))))
		}
		p.processed.Add(1)
		if _, err := p.deliver(ctx, derived); err != nil {
			return err
		}
	}
	return nil
}

// applyDecision records a ban, applies it to the firewall when a backend is
// configured, and tells the owner either way.
//
// The store refuses a ban for an allowlisted address, and that refusal is
// deliberately not an error here: it is the protection working.
func (p *Pipeline) applyDecision(ctx context.Context, d action.Decision) {
	// The detector times decisions by the event's own clock, so replaying an
	// existing audit log produces decisions whose window is already over.
	// Those are history, not an attack in progress: blocking an address over a
	// burst from last Tuesday helps nobody, and on a first start with
	// read_from_start it would flood the chat.
	if !d.Permanent() && !d.Until.After(p.now()) {
		p.log.Info("ban decision skipped: the attack it describes is already over",
			"ip", d.IP, "reason", d.Reason, "until", untilLabel(d.Until),
			"note", "normal while reading an audit log that was written before the agent started")
		return
	}

	ban, created, err := p.opt.Store.EnsureBan(d.IP, d.Reason, d.Until)
	if err != nil {
		if errors.Is(err, store.ErrAllowlisted) {
			p.log.Info("ban refused: the address is allowlisted", "ip", d.IP, "reason", d.Reason)
			return
		}
		p.log.Error("cannot record the ban", "ip", d.IP, "error", err)
		return
	}
	if !created {
		return // an active decision is not another offence
	}
	p.banned.Add(1)

	var applyErr error
	d = action.Decision{IP: ban.IP, Until: ban.Until, Reason: ban.Reason}
	if p.opt.Banner != nil {
		applyErr = p.opt.Banner.Ban(ctx, d)
		if applyErr != nil {
			p.log.Error("the firewall refused the ban", "ip", d.IP, "error", applyErr)
		} else if err := p.opt.Store.MarkBanApplied(d.IP); err != nil {
			applyErr = err
			p.log.Warn("cannot mark the ban as applied", "ip", d.IP, "error", err)
		} else {
			ban.Applied = true
		}
	}
	p.log.Warn("ban decision recorded",
		"ip", d.IP, "reason", d.Reason, "until", untilLabel(d.Until),
		"repeat", ban.Count, "applied", applyErr == nil && p.opt.Banner != nil)

	if p.planner != nil {
		if err := p.enqueueNotice(ctx, p.planner.PlanBan(ban, applyErr)); err != nil {
			p.failDelivery(err)
		}
		return
	}
	if err := p.opt.Notifier.NotifyBan(ctx, ban, applyErr); err != nil {
		p.log.Error("cannot report the ban", "ip", d.IP, "error", err)
	}
}

// autoAllowlist protects the source of the first successful login after the
// agent starts. Without it, an owner whose address changes — carrier NAT, a
// phone, a dynamic home line — can be banned by their own agent after a few
// typos, with no way back in.
func (p *Pipeline) autoAllowlist(ctx context.Context, ev model.Event) {
	if !p.opt.AutoAllowlistFirstLogin ||
		ev.Kind != model.KindSSHLoginOK ||
		ev.SrcIP == "" {
		return
	}
	if p.opt.Store.GetMeta(metaFirstLoginAllowed) != "" {
		return
	}
	if p.opt.Store.IsAllowed(ev.SrcIP) {
		// Already protected; record that the one-off has happened anyway.
		_ = p.opt.Store.SetMeta(metaFirstLoginAllowed, ev.SrcIP)
		return
	}
	if err := p.opt.Store.Allow(ev.SrcIP, "first successful login after start"); err != nil {
		p.log.Error("cannot allowlist the first login", "ip", ev.SrcIP, "error", err)
		return
	}
	if err := p.opt.Store.SetMeta(metaFirstLoginAllowed, ev.SrcIP); err != nil {
		p.log.Warn("cannot record the first-login allowlisting", "error", err)
	}
	p.log.Info("the first successful login was allowlisted", "ip", ev.SrcIP, "user", ev.User)

	if p.planner != nil {
		if err := p.enqueueNotice(ctx, p.planner.PlanMessage("ui.allow.auto", map[string]string{"ip": ev.SrcIP})); err != nil {
			p.failDelivery(err)
		}
		return
	}
	if err := p.opt.Notifier.NotifyMessage(ctx, "ui.allow.auto", map[string]string{"ip": ev.SrcIP}); err != nil {
		p.log.Warn("cannot report the allowlisting", "error", err)
	}
}

// reapplyBans pushes the still-active bans from the store into the firewall.
// The firewall is rebuilt from scratch at startup, so this is what makes the
// store the source of truth rather than whatever survived a reboot.
func (p *Pipeline) reapplyBans(ctx context.Context) {
	if p.opt.Banner == nil {
		return
	}
	now := p.now()
	applied, failed := 0, 0
	for _, b := range p.opt.Store.Bans() {
		if !b.Active(now) {
			continue
		}
		if p.opt.Store.IsAllowed(b.IP) {
			continue
		}
		err := p.opt.Banner.Ban(ctx, action.Decision{IP: b.IP, Until: b.Until, Reason: b.Reason})
		if err != nil {
			failed++
			if saveErr := p.opt.Store.MarkBanUnapplied(b.IP); saveErr != nil {
				p.log.Warn("cannot clear the failed ban confirmation", "ip", b.IP, "error", saveErr)
			}
			p.log.Warn("cannot reapply a ban", "ip", b.IP, "error", err)
			continue
		}
		applied++
		if err := p.opt.Store.MarkBanApplied(b.IP); err != nil {
			p.log.Warn("cannot save the reapplied ban state", "ip", b.IP, "error", err)
		}
	}
	if applied > 0 || failed > 0 {
		p.log.Info("bans reapplied to the firewall", "applied", applied, "failed", failed)
	}
}

func (p *Pipeline) deliver(ctx context.Context, ev model.Event) (bool, error) {
	added, err := p.persistEvent(ev)
	if added && err == nil {
		err = p.notifyEvent(ctx, ev)
	}
	return added, err
}

func (p *Pipeline) persistEvent(ev model.Event) (bool, error) {
	var plan *delivery.Plan
	if p.planner != nil {
		if ev.Time.IsZero() {
			ev.Time = p.now()
		}
		if ev.ID == "" {
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return false, err
			}
			ev.ID = fmt.Sprintf("%x", nonce)
		}
		prepared := p.planner.PlanEvent(ev)
		plan = &prepared
	}
	committed, err := p.opt.Store.AppendEventWithPlan(ev, plan)
	added := committed.Added
	if err != nil {
		p.log.Error("cannot store the event", "kind", ev.Kind, "error", err)
		select {
		case p.fatal <- err:
		default:
		}
		return false, err
	}
	return added, nil
}

func (p *Pipeline) notifyEvent(ctx context.Context, ev model.Event) error {
	if p.outbox != nil {
		return p.recoverDeliveries(ctx)
	}
	if err := p.opt.Notifier.Notify(ctx, ev); err != nil {
		p.log.Error("cannot send the alert", "kind", ev.Kind, "error", err)
		return nil
	}
	p.reported.Add(1)
	p.log.Debug("event handled",
		"kind", ev.Kind, "severity", ev.Severity.String(), "user", ev.User, "ip", ev.SrcIP)
	return nil
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

func detectorName(d detect.Detector) string {
	if d == nil {
		return "none"
	}
	return d.Name()
}

func bannerName(b action.Banner) string {
	if b == nil {
		return "none"
	}
	return b.Name()
}

func untilLabel(t time.Time) string {
	if t.IsZero() {
		return "permanent"
	}
	return t.Format(time.RFC3339)
}

func (p *Pipeline) purgeOldEvents() {
	removed, err := p.opt.Store.Purge()
	if err != nil {
		p.log.Error("cannot purge old events", "error", err)
		return
	}
	if removed > 0 {
		p.log.Info("old event files removed", "files", removed)
		if p.outbox != nil {
			days, err := p.opt.Store.DeliveryDays()
			if err == nil {
				err = p.outbox.PruneCursors(days)
			}
			if err != nil {
				p.failDelivery(err)
			}
		}
	}
}

// Counters reports what the pipeline has done, for diagnostics.
func (p *Pipeline) Counters() (processed, reported, skipped uint64) {
	reported = p.reported.Load()
	if p.outbox != nil {
		reported = p.outbox.Stats().Delivered
	}
	return p.processed.Load(), reported, p.skipped.Load()
}

// Banned reports how many ban decisions have been taken, for /debug.
func (p *Pipeline) Banned() uint64 { return p.banned.Load() }

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

	items := []DiagItem{
		{Key: "ui.diag.events", Value: strconv.FormatUint(processed, 10)},
		{Key: "ui.diag.alerts", Value: strconv.FormatUint(reported, 10)},
		{Key: "ui.diag.skipped", Value: strconv.FormatUint(skipped, 10)},
		{Key: "ui.diag.audit_log", Value: auditLog},
		{Key: "ui.diag.offset", Value: strconv.FormatInt(p.tailer.LastOffset(), 10)},
		{Key: "ui.diag.source", Value: p.tailer.Status()},
		{Key: "ui.diag.detector", Value: detectorName(p.opt.Detector)},
		{Key: "ui.diag.banner", Value: bannerName(p.opt.Banner)},
		{Key: "ui.diag.bans", Value: strconv.FormatUint(p.Banned(), 10)},
	}
	if s := p.PanelCertStatus(); s != "" {
		items = append(items, DiagItem{Key: "ui.diag.panel_cert", Value: s})
	}
	return items
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

// certResult is one look at the certificate the panel serves.
type certResult struct {
	cert netcheck.ServedCert
	err  error
}

// watchPanelCert looks at the served certificate a minute after the start
// (the proxy may still be getting it) and then every PanelCertEvery. The TLS
// handshake runs here, off the main loop, so a slow or dead port never holds
// up reading the audit log.
func (p *Pipeline) watchPanelCert(ctx context.Context, out chan<- certResult) {
	wait := time.Minute
	if p.opt.PanelCertEvery < wait {
		wait = p.opt.PanelCertEvery
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = p.opt.PanelCertEvery
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		c, err := netcheck.CheckServed(cctx, p.opt.PanelURL, nil)
		cancel()
		select {
		case out <- certResult{c, err}:
		case <-ctx.Done():
			return
		}
	}
}

// judgePanelCert turns a look at the certificate into a status line and, when
// something is wrong, one alert per cooldown.
func (p *Pipeline) judgePanelCert(ctx context.Context, r certResult) {
	now := p.now()
	problem, status := "", ""
	if r.err != nil {
		// Not reachable from this machine says little about the outside, and a
		// proxy being restarted is normal: noted, not alerted.
		status = "unknown: " + r.err.Error()
		p.log.Warn("cannot inspect the panel certificate", "url", p.opt.PanelURL, "error", r.err)
	} else {
		problem = netcheck.CertProblem(r.cert, now, p.opt.PanelCertTrust)
		status = fmt.Sprintf("ok, valid until %s (%s left)", r.cert.NotAfter.UTC().Format(time.RFC3339),
			r.cert.NotAfter.Sub(now).Round(time.Minute))
		if problem != "" {
			status = "PROBLEM: " + problem
		}
	}
	p.certMu.Lock()
	p.certStatus = status
	firing, at := p.certFiring, p.certAt
	p.certMu.Unlock()
	if r.err != nil {
		return
	}
	if problem == "" {
		if firing {
			p.log.Info("the panel certificate is fine again", "status", status)
			p.certMu.Lock()
			p.certFiring = false
			p.certMu.Unlock()
		}
		return
	}
	if firing && now.Sub(at) < 6*time.Hour {
		return
	}
	p.certMu.Lock()
	p.certFiring, p.certAt = true, now
	p.certMu.Unlock()
	p.log.Warn("panel certificate problem", "url", p.opt.PanelURL, "problem", problem)
	ev := semantic.PanelCertProblem(p.opt.Host, problem)
	ev.Time = now
	p.deliver(ctx, ev)
}

// PanelCertStatus is the last verdict on the served certificate, for the
// diagnostics; empty when the panel is not published over https.
func (p *Pipeline) PanelCertStatus() string {
	if !strings.HasPrefix(p.opt.PanelURL, "https://") {
		return ""
	}
	p.certMu.Lock()
	defer p.certMu.Unlock()
	if p.certStatus == "" {
		return "not checked yet"
	}
	return p.certStatus
}
