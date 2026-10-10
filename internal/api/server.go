package api

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RsNest/auditdsec/internal/action"
	"github.com/RsNest/auditdsec/internal/config"
	"github.com/RsNest/auditdsec/internal/decision"
	"github.com/RsNest/auditdsec/internal/i18n"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/notify/telegram"
	"github.com/RsNest/auditdsec/internal/pipeline"
	"github.com/RsNest/auditdsec/internal/sanitize"
	"github.com/RsNest/auditdsec/internal/store"
	"github.com/RsNest/auditdsec/internal/web"
)

// Enforcer is the part of a firewall backend the panel needs.
type Enforcer interface {
	Ban(ctx context.Context, d action.Decision) error
	Unban(ctx context.Context, ip string) error
}

// Runtime is what only the running pipeline knows.
type Runtime interface {
	Counters() (processed, reported, skipped uint64)
	Diagnostics() []pipeline.DiagItem
}

// Options wires the server to the rest of the agent.
type Options struct {
	Config   *config.Config
	Store    *store.Store
	Enforcer Enforcer // nil when no firewall backend is configured
	// Decisions is the service every interface uses for bans and the allowlist.
	// Without one, a service over Store and Enforcer is made.
	Decisions *decision.Service
	Runtime   Runtime // may be nil in tests
	Telegram  *telegram.Managed
	Host      string
	Version   string
	Started   time.Time
	Logger    *slog.Logger
	Now       func() time.Time
}

// Server is the panel's HTTP server.
type Server struct {
	opt        Options
	log        *slog.Logger
	now        func() time.Time
	cred       credState
	global     *limiter
	finalizeMu sync.Mutex
	proxies    proxySet
	sessions   *sessions
	limit      *limiter
	hashing    chan struct{} // bounds concurrent password hashing
	static     http.Handler
	mux        *http.ServeMux

	statMu  sync.Mutex
	statAt  time.Time
	statVal statusDigest
}

// New builds the server. It fails on a missing or malformed password rather
// than starting open.
func New(o Options) (*Server, error) {
	if o.Config == nil || o.Store == nil {
		return nil, errors.New("api: Config and Store are required")
	}
	w := o.Config.Web
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Decisions == nil {
		var banner action.Banner
		if o.Enforcer != nil {
			banner = enforcerBanner{o.Enforcer}
		}
		o.Decisions = decision.New(decision.Options{Store: o.Store, Banner: banner, Log: o.Logger, Now: o.Now})
	}
	proxies, err := parseProxies(w.TrustedProxies)
	if err != nil {
		return nil, err
	}

	s := &Server{
		opt: o, log: o.Logger, now: o.Now,
		proxies:  proxies,
		sessions: newSessions(w.SessionTTL, o.Now),
		limit:    newLimiter(o.Now),
		global:   newLimiterN(o.Now, globalFailLimit),
		hashing:  make(chan struct{}, 2),
		static:   web.Handler(),
		mux:      http.NewServeMux(),
	}
	if err := s.loadCreds(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

// decoyHash builds a hash with the same cost as the real one over a random
// password, so verifying against it takes the same time and never matches.
func decoyHash(real parsedHash) (parsedHash, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return parsedHash{}, err
	}
	salt := make([]byte, len(real.salt))
	if _, err := rand.Read(salt); err != nil {
		return parsedHash{}, err
	}
	key, err := pbkdf2.Key(sha256.New, string(secret), salt, real.iter, len(real.key))
	if err != nil {
		return parsedHash{}, err
	}
	return parsedHash{iter: real.iter, salt: salt, key: key}, nil
}

// Handler is the whole site: the API under /api/ and the panel everywhere else.
func (s *Server) Handler() http.Handler { return s.mux }

// ListenAndServe serves until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.opt.Config.Web.Listen,
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) routes() {
	api := func(pattern string, auth bool, h http.HandlerFunc) {
		s.mux.Handle(pattern, s.guard(auth, h))
	}
	api("POST /api/v1/login", false, s.handleLogin)
	api("POST /api/v1/logout", false, s.handleLogout)
	api("GET /api/v1/setup/state", false, s.handleSetupState)
	api("POST /api/v1/setup/complete", false, s.handleSetupComplete) // checks for a setup session itself
	api("GET /api/v1/status", true, s.handleStatus)
	api("GET /api/v1/events", true, s.handleEvents)
	api("GET /api/v1/explain/{kind}", true, s.handleExplain)
	api("GET /api/v1/bans", true, s.handleBans)
	api("GET /api/v1/suspects", true, s.handleSuspects)
	api("POST /api/v1/bans", true, s.handleBan)
	api("DELETE /api/v1/bans/{ip}", true, s.handleUnban)
	api("GET /api/v1/allowlist", true, s.handleAllowlist)
	api("POST /api/v1/allowlist", true, s.handleAllow)
	api("DELETE /api/v1/allowlist/{ip}", true, s.handleUnallow)
	api("POST /api/v1/mute", true, s.handleMute)
	api("DELETE /api/v1/mute", true, s.handleUnmute)
	api("GET /api/v1/config", true, s.handleConfig)
	api("GET /api/v1/settings/telegram", true, s.handleTelegram)
	api("PUT /api/v1/settings/telegram", true, s.handleTelegram)
	api("POST /api/v1/settings/telegram/verify", true, s.handleTelegram)
	api("POST /api/v1/settings/telegram/test", true, s.handleTelegram)
	api("GET /api/v1/diagnostics", true, s.handleDiagnostics)
	api("GET /api/v1/deliveries", true, s.handleDeliveries)
	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		fail(w, http.StatusNotFound, "not_found", "no such endpoint")
	})
	s.mux.Handle("/", s.static)
}

// guard applies the rules every API call shares: no caching, same-origin only,
// a marker header on anything that changes state, and a valid session.
func (s *Server) guard(auth bool, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Type", "application/json; charset=utf-8")

		if o := r.Header.Get("Origin"); o != "" && !sameOrigin(o, r.Host) {
			fail(w, http.StatusForbidden, "forbidden", "cross-origin request refused")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-Requested-With") != "auditdsec" {
				fail(w, http.StatusForbidden, "forbidden", "missing X-Requested-With")
				return
			}
		}
		if auth && !s.sessions.valid(bearer(r)) {
			fail(w, http.StatusUnauthorized, "unauthorized", "sign in first")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		next(w, r)
	})
}

func sameOrigin(origin, host string) bool {
	i := strings.Index(origin, "://")
	return i > 0 && strings.EqualFold(origin[i+3:], host)
}

func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return ""
}

// clientIP is the address the request came from. X-Forwarded-For is believed
// only when the peer is one of the configured proxies: otherwise anyone could
// forge the address that the rate limiter counts and the log records, which
// would make both useless.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, peerOK := netip.ParseAddr(host)
	if peerOK == nil && s.fromProxy(peer) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// The proxy appends the peer it saw, so the last entry is the one
			// it vouches for; earlier ones come from the client.
			if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return a.Unmap().String()
			}
		}
	}
	if peerOK == nil {
		return peer.Unmap().String()
	}
	return host
}

func (s *Server) fromProxy(peer netip.Addr) bool {
	return s.proxies.contains(peer)
}

// proxySet holds the networks a reverse proxy may connect from.
type proxySet struct {
	prefixes []netip.Prefix
	addrs    []netip.Addr
}

func parseProxies(list []string) (proxySet, error) {
	var out proxySet
	for _, raw := range list {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if p, err := netip.ParsePrefix(raw); err == nil {
			out.prefixes = append(out.prefixes, p)
			continue
		}
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return proxySet{}, fmt.Errorf("web.trusted_proxies: %q is not an address or a network", raw)
		}
		out.addrs = append(out.addrs, a.Unmap())
	}
	return out, nil
}

func (p proxySet) contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, pre := range p.prefixes {
		if pre.Contains(a) {
			return true
		}
	}
	for _, want := range p.addrs {
		if want == a {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, slug, msg string) {
	writeJSON(w, code, map[string]string{"error": slug, "message": msg})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "malformed request body")
		return false
	}
	return true
}

// ---- sign-in ----

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if blocked, wait := s.limit.blocked(ip); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		fail(w, http.StatusTooManyRequests, "throttled", "too many attempts, try later")
		return
	}
	var in struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Password) > 512 || len(in.Login) > 128 {
		fail(w, http.StatusBadRequest, "bad_request", "too long")
		return
	}
	snap := s.cred.snapshot()
	if !snap.ready {
		s.bootstrapLogin(w, ip, in.Login, in.Password)
		return
	}
	select {
	case s.hashing <- struct{}{}:
		defer func() { <-s.hashing }()
	default:
		w.Header().Set("Retry-After", "2")
		fail(w, http.StatusTooManyRequests, "throttled", "busy, try again")
		return
	}

	got := sha256.Sum256([]byte(in.Login))
	loginOK := subtle.ConstantTimeCompare(got[:], snap.sum[:]) == 1
	h := snap.hash
	if !loginOK {
		h = snap.dummy
	}
	passOK := h.verify(in.Password)
	if !loginOK || !passOK {
		s.limit.failed(ip)
		s.log.Warn("panel sign-in failed", "ip", ip)
		fail(w, http.StatusUnauthorized, "bad_credentials", "wrong login or password")
		return
	}
	s.limit.ok(ip)
	token, exp := s.sessions.create()
	s.log.Info("panel sign-in", "ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires": exp.UTC().Format(time.RFC3339)})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessions.revoke(bearer(r))
	w.WriteHeader(http.StatusNoContent)
}

// ---- reading ----

func (s *Server) lang(r *http.Request) i18n.Lang {
	if q := r.URL.Query().Get("lang"); q != "" {
		if l, err := i18n.ParseLang(q); err == nil {
			return l
		}
	}
	return s.opt.Config.Language()
}

type eventJSON struct {
	ID       string            `json:"id"`
	EventID  string            `json:"event_id,omitempty"`
	Time     time.Time         `json:"time"`
	Host     string            `json:"host"`
	Kind     model.Kind        `json:"kind"`
	Severity string            `json:"severity"`
	User     string            `json:"user,omitempty"`
	SrcIP    string            `json:"src_ip,omitempty"`
	Summary  string            `json:"summary"`
	Args     map[string]string `json:"args,omitempty"`
	Raw      string            `json:"raw,omitempty"`
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	lang := s.lang(r)

	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			fail(w, http.StatusBadRequest, "bad_request", "bad limit")
			return
		}
		limit = min(n, 200)
	}
	var sev model.Severity = -1
	if v := q.Get("severity"); v != "" {
		p, err := model.ParseSeverity(v)
		if err != nil {
			fail(w, http.StatusBadRequest, "bad_request", "bad severity")
			return
		}
		sev = p
	}
	kind := model.Kind(q.Get("kind"))
	if kind != "" && !model.ValidKind(kind) {
		fail(w, http.StatusBadRequest, "bad_request", "unknown kind")
		return
	}
	since, until := timeParam(w, q.Get("since")), timeParam(w, q.Get("until"))
	if since.Equal(errTime) || until.Equal(errTime) {
		return
	}
	ipQ, userQ := strings.ToLower(q.Get("ip")), strings.ToLower(q.Get("user"))
	needle := strings.ToLower(q.Get("q"))
	before := q.Get("before")

	items := make([]eventJSON, 0, limit+1)
	err := s.opt.Store.Scan(since, until, func(id string, ev model.Event) bool {
		if before != "" && id >= before {
			return true
		}
		if sev >= 0 && ev.Severity != sev {
			return true
		}
		if kind != "" && ev.Kind != kind {
			return true
		}
		if ipQ != "" && !strings.Contains(strings.ToLower(ev.SrcIP), ipQ) {
			return true
		}
		if userQ != "" && !strings.Contains(strings.ToLower(ev.User), userQ) {
			return true
		}
		// Events written by older versions may hold unmasked evidence: it is
		// masked on the way out, before the search can match against it, so
		// neither the answer nor a query can reveal it. Stored files are not
		// rewritten.
		ev = sanitize.Event(ev)
		summary := i18n.T(lang, ev.SummaryKey, ev.Args)
		if needle != "" && !strings.Contains(strings.ToLower(summary+" "+ev.User+" "+ev.SrcIP+" "+ev.Raw), needle) {
			return true
		}
		items = append(items, eventJSON{
			ID: id, EventID: ev.ID, Time: ev.Time.UTC(), Host: ev.Host, Kind: ev.Kind, Severity: ev.Severity.String(),
			User: ev.User, SrcIP: ev.SrcIP, Summary: summary, Args: ev.Args, Raw: ev.Raw,
		})
		return len(items) <= limit
	})
	if err != nil {
		s.log.Error("cannot read events", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "cannot read events")
		return
	}
	var next any
	if len(items) > limit {
		items = items[:limit]
		next = items[limit-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next": next})
}

var errTime = time.Unix(1, 1)

// timeParam parses an optional RFC 3339 time; on a bad value it answers 400
// and returns errTime.
func timeParam(w http.ResponseWriter, v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "times must be RFC 3339")
		return errTime
	}
	return t
}

func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	kind := model.Kind(r.PathValue("kind"))
	if !model.ValidKind(kind) {
		fail(w, http.StatusNotFound, "not_found", "unknown event kind")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"kind": string(kind),
		"text": i18n.T(s.lang(r), "explain."+string(kind), nil),
	})
}

func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.activeBans())
}

func (s *Server) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		IP     string    `json:"ip"`
		Added  time.Time `json:"added"`
		Source string    `json:"source"`
	}
	out := []entry{}
	for _, e := range s.opt.Store.Allowlist() {
		src := "manual"
		if strings.Contains(e.Note, "first successful login") {
			src = "first_login"
		}
		out = append(out, entry{IP: e.IP, Added: e.AddedAt.UTC(), Source: src})
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- status ----

type statusDigest struct {
	events24, warn24, crit24 int
	byKind                   map[string]int
	hourly                   []map[string]any
}

func (s *Server) digest() statusDigest {
	s.statMu.Lock()
	defer s.statMu.Unlock()
	now := s.now().UTC()
	if !s.statAt.IsZero() && now.Sub(s.statAt) < 5*time.Second {
		return s.statVal
	}
	start := now.Truncate(time.Hour).Add(-23 * time.Hour)
	d := statusDigest{byKind: map[string]int{}}
	buckets := make([][3]int, 24)
	_ = s.opt.Store.Scan(start, now, func(_ string, ev model.Event) bool {
		d.events24++
		d.byKind[string(ev.Kind)]++
		switch ev.Severity {
		case model.SevWarn:
			d.warn24++
		case model.SevCritical:
			d.crit24++
		}
		if i := int(ev.Time.UTC().Sub(start) / time.Hour); i >= 0 && i < 24 {
			buckets[i][int(ev.Severity)]++
		}
		return true
	})
	for i := 0; i < 24; i++ {
		d.hourly = append(d.hourly, map[string]any{
			"hour": start.Add(time.Duration(i) * time.Hour).Format(time.RFC3339),
			"info": buckets[i][0], "warn": buckets[i][1], "critical": buckets[i][2],
		})
	}
	s.statAt, s.statVal = now, d
	return d
}

func (s *Server) counters(d statusDigest) map[string]any {
	var processed, reported, skipped uint64
	if s.opt.Runtime != nil {
		processed, reported, skipped = s.opt.Runtime.Counters()
	}
	out := map[string]any{
		"events_24h": d.events24, "critical_24h": d.crit24, "warn_24h": d.warn24,
		"events_total": processed, "alerts_sent": reported,
		"lines_skipped": skipped, "rate_limited": 0,
	}
	if runtime, ok := s.opt.Runtime.(deliveryRuntime); ok {
		stats, _ := runtime.DeliveryState()
		out["delivery"] = stats
		out["alerts_sent"] = stats.Delivered
		out["rate_limited"] = stats.Deferred
	}
	return out
}

func (s *Server) auditHealth() map[string]any {
	c := s.opt.Config
	fi, err := os.Stat(c.AuditLog)
	if err != nil {
		return map[string]any{"healthy": false, "last_write": nil}
	}
	healthy := true
	if c.Heartbeat.Enabled && c.Heartbeat.StaleAfter > 0 && s.now().Sub(fi.ModTime()) > c.Heartbeat.StaleAfter {
		healthy = false
	}
	return map[string]any{"healthy": healthy, "last_write": fi.ModTime().UTC().Format(time.RFC3339)}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	c := s.opt.Config
	d := s.digest()
	var muted any
	if t := s.opt.Store.MutedUntil(); !t.IsZero() {
		muted = t.UTC().Format(time.RFC3339)
	}
	var last any
	if rec := s.opt.Store.Recent(1); len(rec) == 1 {
		last = rec[0].Time.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host": s.opt.Host, "profile": c.Profile, "version": s.opt.Version,
		"uptime_seconds": int(s.now().Sub(s.opt.Started).Seconds()),
		"lang":           string(c.Language()), "debug": c.Debug, "log_level": c.Log.Level,
		"ban": map[string]any{
			"backend": c.Ban.Backend, "dry_run": c.Ban.DryRun,
			"enforcing": c.EnforcesBans() && !c.Ban.DryRun,
		},
		"muted_until":     muted,
		"auditd":          s.auditHealth(),
		"counters":        s.counters(d),
		"bans_active":     len(s.activeBans()),
		"allowlist_count": len(s.opt.Store.Allowlist()),
		"last_event_time": last,
		"by_kind":         d.byKind,
		"hourly":          d.hourly,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	c := s.opt.Config
	var quiet any
	if _, _, on := c.QuietHours(); on {
		quiet = c.Telegram.QuietFrom + "-" + c.Telegram.QuietTo
	}
	ids := c.Telegram.ChatIDs
	if ids == nil {
		ids = []int64{}
	}
	minSeverity, rate := c.Telegram.MinSeverity, c.Telegram.RatePerMinute
	if s.opt.Telegram != nil {
		v := s.opt.Telegram.View()
		ids, minSeverity, rate = v.ChatIDs, v.MinSeverity, v.RatePerMinute
		quiet = nil
		if v.QuietFrom != "" {
			quiet = v.QuietFrom + "-" + v.QuietTo
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host": s.opt.Host, "profile": c.Profile, "lang": c.Lang,
		"telegram": map[string]any{
			"token": "***", "chat_ids": ids, "min_severity": minSeverity,
			"quiet_hours": quiet, "dedup_window": shortDur(c.Telegram.DedupWindow),
			"rate_per_minute": rate, "retention_days": c.Store.RetentionDays,
		},
		"detect": map[string]any{
			"enabled": c.Detect.Enabled, "window": shortDur(c.Detect.Window),
			"fail_threshold": c.Detect.FailThreshold, "success_after_failures": c.Detect.SuccessAfterFailures,
		},
		"ban": map[string]any{
			"backend": c.Ban.Backend, "dry_run": c.Ban.DryRun, "table": c.Ban.Table,
			"auto_allowlist": c.Ban.AutoAllowlist,
		},
		"heartbeat": map[string]any{"enabled": c.Heartbeat.Enabled, "stale_after": shortDur(c.Heartbeat.StaleAfter)},
		"log":       map[string]any{"file": c.Log.File, "level": c.Log.Level, "max_size_mb": c.Log.MaxSizeMB, "keep": c.Log.MaxBackups},
	})
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	c := s.opt.Config
	d := s.digest()
	out := map[string]any{
		"debug": c.Debug, "log_level": c.Log.Level, "counters": s.counters(d),
		"audit_log": c.AuditLog, "bans_recorded": len(s.opt.Store.Bans()),
		"detector": "none", "banner": c.Ban.Backend,
	}
	if c.Detect.Enabled {
		out["detector"] = "bruteforce"
	}
	if s.opt.Runtime != nil {
		for _, it := range s.opt.Runtime.Diagnostics() {
			switch it.Key {
			case "ui.diag.offset":
				if n, err := strconv.ParseInt(it.Value, 10, 64); err == nil {
					out["offset"] = n
				}
			case "ui.diag.source":
				out["source_status"] = it.Value
			case "ui.diag.detector":
				out["detector"] = it.Value
			case "ui.diag.banner":
				out["banner"] = it.Value
			case "ui.diag.panel_cert":
				out["panel_cert"] = it.Value
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- changing things ----

// shortDur prints a duration the way the config file spells it: 10m, not
// 10m0s, which is what the panel shows beside "repeat grouping window".
func shortDur(d time.Duration) string {
	s := d.Round(time.Second).String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func (s *Server) handleMute(w http.ResponseWriter, r *http.Request) {
	var in struct{ Hours int }
	if !decode(w, r, &in) {
		return
	}
	if in.Hours < 1 || in.Hours > 168 {
		fail(w, http.StatusBadRequest, "bad_request", "hours must be 1 to 168")
		return
	}
	until := s.now().Add(time.Duration(in.Hours) * time.Hour)
	if err := s.opt.Store.Mute(until); err != nil {
		fail(w, http.StatusInternalServerError, "internal", "cannot save")
		return
	}
	s.log.Info("panel: mute", "hours", in.Hours, "by", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"muted_until": until.UTC().Format(time.RFC3339)})
}

func (s *Server) handleUnmute(w http.ResponseWriter, r *http.Request) {
	if err := s.opt.Store.Mute(time.Time{}); err != nil {
		fail(w, http.StatusInternalServerError, "internal", "cannot save")
		return
	}
	s.log.Info("panel: unmute", "by", s.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}
