package update

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultBase is where the metadata of every channel is published: a rolling
// GitHub release holding <channel>.json and <channel>.json.sig. It is public
// and needs no token.
const DefaultBase = "https://github.com/RsNest/auditdsec/releases/download/updates/"

// Hosts a request may be redirected to (GitHub serves release assets from them).
var allowedHosts = map[string]bool{
	"github.com":                            true,
	"objects.githubusercontent.com":         true,
	"release-assets.githubusercontent.com":  true,
	"github-releases.githubusercontent.com": true,
}

// Store keeps the small state across restarts.
type Store interface {
	GetMeta(key string) string
	SetMeta(key, value string) error
}

const metaKey = "update_state"

// Options configure a Checker.
type Options struct {
	Installed Installed
	Channel   string // empty: DefaultChannel
	Arch      string
	Base      string // empty: DefaultBase. Must be https, or http on loopback (tests).
	PublicKey ed25519.PublicKey
	Store     Store
	Client    *http.Client
	Log       *slog.Logger
	Now       func() time.Time
	// Interval between checks (default 6h); each wait gets up to ±Jitter (default 30min).
	Interval, Jitter time.Duration
	// MinManualGap: how often the button may trigger a request (default 1 min).
	MinManualGap time.Duration
	Rand         func() float64
}

// persisted is what survives a restart.
type persisted struct {
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success"`
	LastError   string    `json:"last_error"`
	Commit      string    `json:"commit"`         // the installed build the result was computed for
	Last        *Result   `json:"last,omitempty"` // the last successful evaluation
	Failures    int       `json:"failures"`
}

// View is what the panel shows.
type View struct {
	Checking    bool      `json:"checking"`
	State       string    `json:"state"` // checking, never, or a State* value; "unavailable" after a failed check
	Channel     string    `json:"channel"`
	Installed   Installed `json:"installed"`
	LastChecked time.Time `json:"last_checked"`
	LastSuccess time.Time `json:"last_success"`
	NextCheck   time.Time `json:"next_check"`
	Error       string    `json:"error,omitempty"`
	// Result is the last successful evaluation. After a failed check it is the
	// older one, and State says "unavailable": it is never shown as current.
	Result *Result `json:"result,omitempty"`
}

// Checker polls the metadata in the background and answers the panel.
type Checker struct {
	opt Options
	log *slog.Logger

	mu       sync.Mutex
	st       persisted
	checking bool
	next     time.Time
	kick     chan struct{}
}

// New builds a Checker and restores its state.
func New(o Options) (*Checker, error) {
	if o.Channel == "" {
		o.Channel = DefaultChannel(o.Installed.Version)
	}
	if o.Channel != ChannelStable && o.Channel != ChannelMain {
		return nil, fmt.Errorf("update: unknown channel %q", o.Channel)
	}
	o.Installed.Channel = o.Channel
	if o.Base == "" {
		o.Base = DefaultBase
	}
	if err := checkBase(o.Base); err != nil {
		return nil, err
	}
	if !strings.HasSuffix(o.Base, "/") {
		o.Base += "/"
	}
	if o.Interval <= 0 {
		o.Interval = 6 * time.Hour
	}
	if o.Jitter <= 0 {
		o.Jitter = 30 * time.Minute
	}
	if o.MinManualGap <= 0 {
		o.MinManualGap = time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rand == nil {
		o.Rand = rand.Float64
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	c := &Checker{opt: o, log: o.Log, kick: make(chan struct{}, 1)}
	if o.Client == nil {
		c.opt.Client = newClient()
	}
	if o.Store != nil {
		if v := o.Store.GetMeta(metaKey); v != "" {
			_ = json.Unmarshal([]byte(v), &c.st) // damaged state is just forgotten
			if c.st.Commit != o.Installed.Commit {
				c.st.Last, c.st.LastSuccess = nil, time.Time{} // an update was applied: that comparison is about another build
			}
		}
	}
	return c, nil
}

func checkBase(base string) error {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return errors.New("update: the source is not a URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		if h := u.Hostname(); h == "127.0.0.1" || h == "::1" || h == "localhost" {
			return nil
		}
	}
	return errors.New("update: the source must be https")
}

func newClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
			TLSHandshakeTimeout:   8 * time.Second,
			ResponseHeaderTimeout: 12 * time.Second,
			DisableKeepAlives:     true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" || !allowedHosts[req.URL.Hostname()] {
				return fmt.Errorf("redirect to %s is not allowed", req.URL.Hostname())
			}
			return nil
		},
	}
}

func (c *Checker) save() {
	if c.opt.Store == nil {
		return
	}
	b, err := json.Marshal(c.st)
	if err == nil {
		_ = c.opt.Store.SetMeta(metaKey, string(b))
	}
}

// fetch downloads one file of the channel.
func (c *Checker) fetch(ctx context.Context, name string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.opt.Base+name, nil)
	if err != nil {
		return nil, err
	}
	// Nothing about this server, its events or its user: a fixed agent string.
	req.Header.Set("User-Agent", "auditdsec-update-check")
	req.Header.Set("Accept", "application/json")
	resp, err := c.opt.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the update source answered %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocument+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxDocument {
		return nil, errors.New("the update document is too large")
	}
	return data, nil
}

// Fetch downloads, verifies and evaluates the channel's document without
// touching the saved state (used by the installer's update command).
func (c *Checker) Fetch(ctx context.Context) (Result, error) {
	doc, err := c.fetch(ctx, c.opt.Channel+".json")
	if err != nil {
		return Result{}, err
	}
	return c.evaluate(ctx, doc)
}

func (c *Checker) evaluate(ctx context.Context, doc []byte) (Result, error) {
	if len(c.opt.PublicKey) > 0 {
		sig, err := c.fetch(ctx, c.opt.Channel+".json.sig")
		if err != nil {
			return Result{}, fmt.Errorf("%w (%v)", ErrSignature, err)
		}
		if err := Verify(doc, sig, c.opt.PublicKey); err != nil {
			return Result{}, err
		}
	}
	md, err := Parse(doc)
	if err != nil {
		return Result{}, err
	}
	if md.Channel != c.opt.Channel {
		return Result{}, bad("the document is for channel %q", md.Channel)
	}
	return Evaluate(c.opt.Installed, md, c.opt.Arch), nil
}

// short turns an error into a line safe to show: no URLs with credentials, no
// long output.
func short(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err // the reason, without the address that was asked
	}
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// CheckNow performs one check. A failure is recorded and reported in the view,
// never returned into the caller's flow. A second call while one runs does
// nothing.
func (c *Checker) CheckNow(ctx context.Context) {
	c.mu.Lock()
	if c.checking {
		c.mu.Unlock()
		return
	}
	c.checking = true
	c.mu.Unlock()

	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	res, err := c.Fetch(cctx)
	cancel()

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.opt.Now()
	c.checking = false
	c.st.LastAttempt = now
	if err != nil {
		c.st.Failures++
		c.st.LastError = short(err)
		c.log.Info("the update check did not complete", "error", c.st.LastError, "retry_in", c.retryLocked())
	} else {
		c.st.Last, c.st.Commit = &res, c.opt.Installed.Commit
		c.st.LastSuccess, c.st.LastError, c.st.Failures = now, "", 0
	}
	c.next = now.Add(c.retryLocked())
	c.save()
}

// retryLocked is how long to wait after the last attempt: the normal interval
// with jitter after success, and a growing wait (15 min doubling up to the
// normal interval) after failures.
func (c *Checker) retryLocked() time.Duration {
	if c.st.Failures == 0 {
		j := time.Duration((c.opt.Rand()*2 - 1) * float64(c.opt.Jitter))
		return c.opt.Interval + j
	}
	d := 15 * time.Minute
	for i := 1; i < c.st.Failures && d < c.opt.Interval; i++ {
		d *= 2
	}
	if d > c.opt.Interval {
		d = c.opt.Interval
	}
	return d
}

// Run checks at start (after a short random delay, so a fleet restarted
// together does not call at the same second) and then on schedule, until ctx
// ends. A source that is down never affects the rest of the agent.
func (c *Checker) Run(ctx context.Context) {
	delay := time.Duration(c.opt.Rand() * float64(45*time.Second))
	c.mu.Lock()
	c.next = c.opt.Now().Add(delay)
	c.mu.Unlock()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.kick:
		case <-timer.C:
		}
		c.CheckNow(ctx)
		c.mu.Lock()
		wait := c.next.Sub(c.opt.Now())
		c.mu.Unlock()
		if wait < time.Minute {
			wait = time.Minute
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
	}
}

// ErrTooSoon: the button was pressed again before the minimum gap.
var ErrTooSoon = errors.New("update: a check was made a moment ago")

// Request asks for a check now (the button). It starts one in the background
// unless one ran or is running within the minimum gap.
func (c *Checker) Request() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checking || c.opt.Now().Sub(c.st.LastAttempt) < c.opt.MinManualGap {
		return ErrTooSoon
	}
	select {
	case c.kick <- struct{}{}:
	default:
	}
	return nil
}

// View returns the current picture for the panel.
func (c *Checker) View() View {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := View{
		Checking: c.checking, Channel: c.opt.Channel, Installed: c.opt.Installed,
		LastChecked: c.st.LastAttempt, LastSuccess: c.st.LastSuccess, NextCheck: c.next, Error: c.st.LastError,
		Result: c.st.Last,
	}
	switch {
	case c.checking:
		v.State = "checking"
	case c.st.LastAttempt.IsZero():
		v.State = "never"
	case c.st.LastError != "":
		v.State = "unavailable"
	case c.st.Last != nil:
		v.State = c.st.Last.State
		// A result computed for an earlier build says nothing about this one.
		if c.st.Last.Latest.Commit == c.opt.Installed.Commit && c.opt.Installed.Commit != "" {
			v.State = StateUpToDate
		}
	default:
		v.State = "never"
	}
	return v
}
