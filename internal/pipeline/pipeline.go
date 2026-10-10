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
	"github.com/RsNest/auditdsec/internal/auditlog"
	"github.com/RsNest/auditdsec/internal/decision"
	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/detect"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/netcheck"
	"github.com/RsNest/auditdsec/internal/parse"
	"github.com/RsNest/auditdsec/internal/sanitize"
	"github.com/RsNest/auditdsec/internal/semantic"
	"github.com/RsNest/auditdsec/internal/session"
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

// MetaFirstLoginAllowed records that the owner's address has been protected,
// so it happens once per installation rather than on every restart.
const MetaFirstLoginAllowed = "first_login_allowlisted"

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
	// Sessions, when set, attributes audited actions to login sessions. It is
	// context for people only: nothing here feeds detection or bans.
	Sessions *session.Tracker
	// Journal, when set, feeds Sessions from the systemd journal in the
	// background. It is optional and never blocks ingestion.
	Journal *session.Follower
	// Banner applies decisions on the host. Nil, or the no-op banner, means
	// decisions are recorded and reported but nothing is blocked.
	Banner action.Banner
	// AutoAllowlistFirstLogin protects the source of the first successful
	// login after startup, which is almost always the person installing the
	// agent. It is what stops the detector locking its owner out.
	AutoAllowlistFirstLogin bool

	// Decisions is the service for bans, unbans and the allowlist; the panel
	// and the bot are given the same one. Without it, one is made from Store
	// and Banner. ReconcileEvery is how often the firewall is compared with the
	// records (default two minutes).
	Decisions      *decision.Service
	ReconcileEvery time.Duration

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
	dec        *decision.Service
	noticeKick chan struct{}

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
	heartbeatState  auditlog.State
	detectReady     bool
	sessionPath     string
	noticed         map[string]bool

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
	if o.Decisions == nil {
		o.Decisions = decision.New(decision.Options{Store: o.Store, Banner: o.Banner, Log: o.Logger, Now: o.Now})
	}
	p := &Pipeline{
		dec:           o.Decisions,
		noticeKick:    make(chan struct{}, 1),
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
	if o.Sessions != nil && o.StateDir != "" {
		p.sessionPath = filepath.Join(o.StateDir, "sessions.json")
		discarded, err := o.Sessions.Load(p.sessionPath)
		switch {
		case err != nil:
			p.log.Warn("the saved session table is unreadable and was ignored", "error", err)
		case discarded:
			p.log.Info("the saved session table belongs to another boot and was discarded")
		}
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
	// What the firewall holds is compared with the records before anything
	// else: a block lost across a restart is put back, one that was never
	// confirmed is retried. The comparison then repeats in the background.
	go p.reconcileLoop(ctx)
	if p.opt.Journal != nil {
		go p.opt.Journal.Run(ctx)
	}
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

	if err := p.startDetection(ctx); err != nil {
		return err
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

		case <-p.noticeKick:
			p.flushBanNotices(ctx)

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
		// Never the content: a secret can be split over the records of one
		// event (a1="-p" a2="secret"), so a single line cannot be masked on
		// its own. The sanitized event is logged once it is assembled.
		p.log.Debug("audit line", "start", line.Start.Offset, "bytes", len(lineText), "type", sanitize.RecordType(lineText))
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
	p.saveSessions()
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
		if p.opt.Sessions != nil {
			p.opt.Sessions.Observe(ae) // learns from every record, reported or not
		}
		ev, reason, ok := p.mapper.MapVerbose(ae)
		if !ok {
			p.log.Debug("audit event ignored",
				"types", strings.Join(ae.Types(), ","),
				"serial", ae.Serial,
				"keys", strings.Join(ae.AuditKeys(), ","),
				"reason", reason)
			continue
		}
		if p.opt.Sessions != nil && ev.Context != nil {
			p.opt.Sessions.Attribute(ev.Context, ae.Time)
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

// handle journals an event, then lets detection consume the journal. The two
// are separate durable steps: the event is committed first, and detection
// advances its own cursor only together with the decisions it produced
// (consumeDetection), so a crash between them leaves the event waiting for
// detection instead of losing its decision. Enforcement happens inside the
// consumption, before the triggering alert is handed to delivery.
func (p *Pipeline) handle(ctx context.Context, ev model.Event) error {
	// The one boundary: whatever built the event, nothing reaches the journal,
	// the notification plan, the detector or a message unsanitized.
	ev = p.silence(sanitize.Event(ev))
	added, err := p.persistEvent(ev)
	if err != nil {
		return err
	}
	if added {
		p.autoAllowlist(ctx, ev)
	}
	if err := p.consumeDetection(ctx); err != nil {
		return err
	}
	if !added {
		return nil
	}
	return p.notifyEvent(ctx, ev)
}

// startDetection initializes the durable detection progress, rebuilds the
// correlation memory from events consumed before this start and consumes the
// events that were journaled but not yet judged. It runs once, before the
// first new line is read.
func (p *Pipeline) startDetection(ctx context.Context) error {
	if p.opt.Detector == nil || p.detectReady {
		return nil
	}
	skipped, err := p.opt.Store.InitDetection()
	if err != nil {
		return fmt.Errorf("pipeline: detection progress: %w", err)
	}
	if skipped > 0 {
		p.log.Warn("detection starts at the end of the existing event journal",
			"journal_days", skipped,
			"note", "events written before this version are history and produce no bans; the recovery guarantee begins now")
	}
	if r, ok := p.opt.Detector.(detect.Restorable); ok {
		now := p.now()
		restored := 0
		err := p.opt.Store.RestoreConsumed(now.Add(-r.Horizon()), func(ev model.Event) {
			r.RestoreFailure(ev, now)
			restored++
		})
		if err != nil {
			return fmt.Errorf("pipeline: restore detection state: %w", err)
		}
		p.log.Debug("detection state restored", "events", restored)
	}
	p.detectReady = true
	if err := p.consumeDetection(ctx); err != nil {
		return err
	}
	p.flushBanNotices(ctx)
	return nil
}

// consumeDetection runs the detector over every journaled event it has not yet
// judged, in journal order. A failure to persist a result stops the agent: the
// detector's in-memory counters already include the event, and the safe way to
// get them right is to restart and rebuild them from the journal.
func (p *Pipeline) consumeDetection(ctx context.Context) error {
	if p.opt.Detector == nil {
		return nil
	}
	if !p.detectReady {
		return p.startDetection(ctx)
	}
	err := p.opt.Store.ConsumeDetection(func(pos delivery.Position, ev model.Event) error {
		return p.detectOne(ctx, pos, ev)
	})
	if err != nil {
		p.log.Error("detection could not record a result; restart the agent to recover from the journal", "error", err)
		select {
		case p.fatal <- err:
		default:
		}
		return err
	}
	return nil
}

// detectOne judges one journaled event. Derived events are persisted first
// under stable IDs (idempotent on a replay); then the decisions and the cursor
// are committed in one write; only then is the firewall touched.
func (p *Pipeline) detectOne(ctx context.Context, pos delivery.Position, ev model.Event) error {
	var res detect.Result
	if ev.Kind != model.KindLoginAfterBruteForce { // derived events never feed detection
		res = p.opt.Detector.Feed(ev)
	}
	var fresh []model.Event
	for n, derived := range res.Events {
		if ev.ID != "" {
			derived.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", ev.ID, derived.Kind, n))))
		}
		p.processed.Add(1)
		derived = sanitize.Event(derived)
		added, err := p.persistEvent(derived)
		if err != nil {
			return err
		}
		if added {
			fresh = append(fresh, derived)
		}
	}

	props := make([]decision.Proposal, 0, len(res.Decisions))
	for _, d := range res.Decisions {
		props = append(props, decision.Proposal{IP: d.IP, Reason: d.Reason, Until: d.Until})
	}
	committed, err := p.dec.CommitDetection(ctx, pos, props, &ev)
	if err != nil {
		return err
	}
	created := false
	for _, c := range committed {
		switch {
		case c.Refused != nil && c.Refused.Reason == decision.ReasonOver:
			// The detector times decisions by the event's own clock, so replaying
			// an old log yields decisions whose window is already over. They are
			// history, not an attack in progress.
			p.log.Info("ban decision skipped: the attack it describes is already over",
				"ip", c.IP, "reason", c.Reason, "until", untilLabel(c.Until),
				"note", "normal while reading an audit log that was written before the agent started")
		case c.Refused != nil:
			p.log.Info("ban refused by policy", "ip", c.IP, "reason", c.Reason, "policy", c.Refused.Error())
		case c.Created:
			created = true
			p.banned.Add(1)
			p.log.Warn("ban decision recorded",
				"ip", c.Ban.IP, "reason", c.Ban.Reason, "until", untilLabel(c.Ban.Until),
				"repeat", c.Ban.Count, "state", c.Ban.State, "backend", c.Ban.Backend)
		}
	}
	if created {
		p.flushBanNotices(ctx)
	}
	for _, d := range fresh {
		if err := p.notifyEvent(ctx, d); err != nil {
			return err
		}
	}
	return nil
}

// flushBanNotices sends the notification of every automatic ban whose notice
// is still owed, then clears the duty. It is what runs after a decision, after
// each reconciliation and at start, so a notice owed at a crash is not lost.
//
// The duty is stored with the decision; the intent ID is derived from the
// decision itself, so a replay builds the same intent. A duty found at start
// (not created by this process) is first looked up in the notification
// journal: a notice already journaled is only imported, never journaled a
// second time. Delivery stays at least once: a crash after the outbox has sent
// a notice and before the duty is cleared can repeat it only if the outbox had
// already forgotten the job.
func (p *Pipeline) flushBanNotices(ctx context.Context) {
	if p.noticed == nil {
		p.noticed = map[string]bool{}
	}
	for _, ban := range p.dec.DueNotices() {
		var applyErr error
		if ban.State == store.StateFailed {
			applyErr = errors.New(ban.LastError)
		}
		if p.planner != nil {
			plan := p.planner.PlanBan(ban, applyErr)
			key := ban.IP + "|" + ban.CreatedAt.Format(time.RFC3339Nano)
			journaled := false
			if len(plan.Intents) > 0 && !p.noticed[key] {
				var err error
				if journaled, err = p.opt.Store.HasNoticeIntent(plan.Intents[0].ID); err != nil {
					p.log.Warn("cannot look up the ban notice in the journal", "ip", ban.IP, "error", err)
				}
			}
			p.noticed[key] = true
			if journaled {
				if err := p.recoverDeliveries(ctx); err != nil {
					p.failDelivery(err)
					return
				}
			} else if err := p.enqueueNotice(ctx, plan); err != nil {
				p.failDelivery(err)
				return
			}
		} else if err := p.opt.Notifier.NotifyBan(ctx, ban, applyErr); err != nil {
			p.log.Error("cannot report the ban", "ip", ban.IP, "error", err)
			continue // the duty stays; the next pass tries again
		}
		if err := p.dec.NoticeSent(ban.IP); err != nil {
			p.log.Warn("cannot record that the ban was reported", "ip", ban.IP, "error", err)
		}
	}
}

// reconcileLoop compares the records with the firewall now and then, off the
// main loop (a slow firewall must not hold up reading), and asks the main loop
// to settle owed notices.
func (p *Pipeline) reconcileLoop(ctx context.Context) {
	p.dec.Run(ctx, p.opt.ReconcileEvery, func(rep decision.Report) {
		if rep.ListErr != nil || rep.Reapplied+rep.Renewed+rep.Released+rep.Orphans+rep.Expired+rep.Failed > 0 {
			p.log.Info("firewall reconciled",
				"checked", rep.Checked, "reapplied", rep.Reapplied, "renewed", rep.Renewed,
				"released", rep.Released, "orphans_removed", rep.Orphans, "expired", rep.Expired,
				"failed", rep.Failed, "unreadable", rep.ListErr != nil)
		}
		select {
		case p.noticeKick <- struct{}{}:
		default:
		}
	})
}

// autoAllowlist protects the source of the first successful login after the
// agent starts. It is off for new installations: a successful login does not
// prove that the owner made it (the first one may be an attacker's), so
// trusting it is a choice. An installation that already relied on it keeps it
// until the owner decides (ban.auto_allowlist).
func (p *Pipeline) autoAllowlist(ctx context.Context, ev model.Event) {
	if !p.opt.AutoAllowlistFirstLogin ||
		ev.Kind != model.KindSSHLoginOK ||
		ev.SrcIP == "" {
		return
	}
	if p.opt.Store.GetMeta(MetaFirstLoginAllowed) != "" {
		return
	}
	if p.opt.Store.IsAllowed(ev.SrcIP) {
		// Already protected; record that the one-off has happened anyway.
		_ = p.opt.Store.SetMeta(MetaFirstLoginAllowed, ev.SrcIP)
		return
	}
	// A login seen while an old log is read is history: it must not make an
	// address permanently trusted.
	if p.now().Sub(ev.Time) > 5*time.Minute {
		return
	}
	res, err := p.dec.Allow(ctx, ev.SrcIP, "first successful login after start", decision.Actor{Origin: decision.FromSystem, Who: "auto_allowlist"})
	if err != nil {
		p.log.Error("cannot allowlist the first login", "ip", ev.SrcIP, "error", err)
		return
	}
	if err := p.opt.Store.SetMeta(MetaFirstLoginAllowed, ev.SrcIP); err != nil {
		p.log.Warn("cannot record the first-login allowlisting", "error", err)
	}
	p.log.Info("the first successful login was allowlisted", "ip", res.Key, "user", ev.User)

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

func (p *Pipeline) deliver(ctx context.Context, ev model.Event) (bool, error) {
	ev = p.silence(sanitize.Event(ev))
	added, err := p.persistEvent(ev)
	if added && err == nil {
		err = p.notifyEvent(ctx, ev)
	}
	return added, err
}

func (p *Pipeline) persistEvent(ev model.Event) (bool, error) {
	ev = sanitize.Event(ev) // idempotent; deliver() reaches here without handle()
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
		prepared := delivery.Plan{Suppressed: "exception"}
		if ev.Suppressed == "" {
			prepared = p.planner.PlanEvent(ev)
		}
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
	if ev.Suppressed != "" {
		return nil // silenced by an exception: stored and shown, not sent
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

// checkHeartbeat reports the audit log becoming unreadable or silent, as two
// different states. An unreadable log means the agent is blind; a silent one may
// be a quiet host or a stopped auditd, and is reported as exactly that. A change
// of state is reported at once; a state that persists repeats only after the
// cooldown.
func (p *Pipeline) checkHeartbeat(ctx context.Context) {
	if !p.opt.HeartbeatEnabled {
		return
	}
	now := p.now()
	st := auditlog.Check(p.opt.AuditLog, now, p.opt.HeartbeatStale)

	if st.State == auditlog.OK {
		if p.heartbeatFiring {
			p.heartbeatFiring, p.heartbeatState = false, ""
			p.log.Info("the audit log is being written again", "path", p.opt.AuditLog)
		}
		return
	}

	cooldown := p.opt.HeartbeatStale
	if cooldown < time.Hour {
		cooldown = time.Hour
	}
	if p.heartbeatFiring && p.heartbeatState == st.State && now.Sub(p.heartbeatAt) < cooldown {
		return
	}
	p.heartbeatFiring, p.heartbeatAt, p.heartbeatState = true, now, st.State
	p.log.Warn("the audit log needs attention", "state", st.State, "reason", st.Detail)

	ev := semantic.AuditHealth(p.opt.Host, st.State, st.Detail)
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
	if p.outbox != nil {
		s := p.outbox.Stats()
		items = append(items, DiagItem{Key: "ui.diag.delivery", Value: fmt.Sprintf("queued=%d, pending=%d (critical=%d), delivered=%d, suppressed=%d, grouped=%d, deferred=%d, retries=%d, failed=%d, cancelled=%d, overflow=%d", s.Queued, s.Pending, s.Critical, s.Delivered, s.Suppressed, s.Grouped, s.Deferred, s.Retries, s.Failed, s.Cancelled, s.Overflow)})
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

// saveSessions writes the session table when it changed. It runs before the
// source cursor moves past the records the table was learned from, so a restart
// either has the session or re-reads the records that define it. Losing it is
// not fatal: it is context only.
func (p *Pipeline) saveSessions() {
	if p.opt.Sessions == nil || !p.opt.Sessions.Dirty() || p.sessionPath == "" {
		return
	}
	if err := p.opt.Sessions.Save(p.sessionPath); err != nil {
		p.log.Warn("cannot save the session table; attribution may be incomplete after a restart", "error", err)
	}
}

// silence marks an event that an exception silences. The event is still
// stored; only its notification (and its incident) is skipped. Critical events
// are never silenced, and detection never sees any of this.
func (p *Pipeline) silence(ev model.Event) model.Event {
	if ev.Suppressed != "" {
		return ev
	}
	if x, ok := p.opt.Store.MatchException(ev); ok {
		ev.Suppressed = x.ID
		p.log.Debug("event silenced by an exception", "exception", x.ID, "kind", ev.Kind)
	}
	return ev
}
