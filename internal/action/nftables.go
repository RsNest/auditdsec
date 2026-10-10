package action

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default names for the firewall objects the agent owns.
const (
	DefaultTable = "auditdsec"
	DefaultSet4  = "blocked4"
	DefaultSet6  = "blocked6"

	// nftPriority puts the drop before the ordinary filter hook (priority 0),
	// so a banned address is dropped whatever the host's own rules say.
	nftPriority = -10

	runTimeout = 10 * time.Second
)

// Runner executes a command. It exists so the firewall logic can be tested
// without root and without touching the machine running the tests.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// RunInput runs a command with the given standard input: `nft -f -`
	// applies a whole script as one transaction, all of it or none of it.
	RunInput(ctx context.Context, input, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands for real.
type ExecRunner struct{}

func (e ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return e.RunInput(ctx, "", name, args...)
}

func (ExecRunner) RunInput(ctx context.Context, input, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if msg == "" {
			return out.Bytes(), err
		}
		return out.Bytes(), fmt.Errorf("%s: %s", err, msg)
	}
	return out.Bytes(), nil
}

// NftablesOptions configures the nftables banner.
type NftablesOptions struct {
	Table  string
	Set4   string
	Set6   string
	Runner Runner
	Logger *slog.Logger
	// DryRun logs the commands instead of running the ones that change state.
	// Worth having for a feature whose failure mode is locking the owner out.
	DryRun bool
}

// Nftables blocks addresses with nftables.
//
// Everything lives in a table of the agent's own ("inet auditdsec"), so the
// host's firewall — ufw, firewalld, docker's chains — is never touched, and
// removing the agent is one `nft delete table` away.
//
// The hook is `input`: it protects the host's own services. Traffic that is
// forwarded to containers on a bridge network does not pass through it, so a
// ban here does not stop an attacker from reaching a published container
// port. That would need a forward hook, which this backend does not install.
type Nftables struct {
	opt NftablesOptions
	log *slog.Logger

	mu    sync.Mutex
	ready bool
}

// NewNftables returns the banner. It does not touch the firewall yet; call
// Ensure for that.
func NewNftables(o NftablesOptions) *Nftables {
	if o.Table == "" {
		o.Table = DefaultTable
	}
	if o.Set4 == "" {
		o.Set4 = DefaultSet4
	}
	if o.Set6 == "" {
		o.Set6 = DefaultSet6
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Nftables{opt: o, log: o.Logger}
}

// Name identifies the backend in logs and in /status.
func (n *Nftables) Name() string {
	if n.opt.DryRun {
		return "nftables (dry run)"
	}
	return "nftables"
}

// DryRun reports whether the backend only logs what it would do.
func (n *Nftables) DryRun() bool { return n.opt.DryRun }

// script is the whole table as one nft script. Applied with `nft -f -` it is a
// single transaction.
func (n *Nftables) script(replace bool) string {
	var b strings.Builder
	if replace {
		fmt.Fprintf(&b, "delete table inet %s\n", n.opt.Table)
	}
	fmt.Fprintf(&b, "add table inet %s\n", n.opt.Table)
	fmt.Fprintf(&b, "add set inet %s %s { type ipv4_addr; flags timeout, interval; }\n", n.opt.Table, n.opt.Set4)
	fmt.Fprintf(&b, "add set inet %s %s { type ipv6_addr; flags timeout, interval; }\n", n.opt.Table, n.opt.Set6)
	fmt.Fprintf(&b, "add chain inet %s input { type filter hook input priority %d; policy accept; }\n", n.opt.Table, nftPriority)
	fmt.Fprintf(&b, "add rule inet %s input ip saddr @%s drop\n", n.opt.Table, n.opt.Set4)
	fmt.Fprintf(&b, "add rule inet %s input ip6 saddr @%s drop\n", n.opt.Table, n.opt.Set6)
	return b.String()
}

var priorityRe = regexp.MustCompile(`hook input priority [^;]*10\b`)

// shapeOK reports whether `nft list table` output has the sets, the chain and
// the two drop rules this backend needs.
func (n *Nftables) shapeOK(listing string) bool {
	for _, want := range []string{
		"set " + n.opt.Set4, "set " + n.opt.Set6, "ipv4_addr", "ipv6_addr",
		"@" + n.opt.Set4 + " drop", "@" + n.opt.Set6 + " drop", "timeout",
	} {
		if !strings.Contains(listing, want) {
			return false
		}
	}
	return priorityRe.MatchString(listing)
}

// Ensure makes the table exist with the right shape, without disturbing a
// table that is already right: the blocks in it are kept, so a restart of the
// agent opens no window in which nothing is blocked. A missing table is
// created, and a table of the wrong shape replaced, each in one transaction.
func (n *Nftables) Ensure(ctx context.Context) error {
	if _, err := n.opt.Runner.Run(ctx, "nft", "--version"); err != nil {
		return fmt.Errorf("nftables is not usable here (%w); install nftables, or run the agent "+
			"with ban.backend: none and let CrowdSec apply the bans", err)
	}
	if n.opt.DryRun {
		n.log.Warn("ban backend is in dry-run mode: decisions are recorded and reported, but nothing is blocked")
		n.mu.Lock()
		n.ready = true
		n.mu.Unlock()
		return nil
	}

	listing, err := n.opt.Runner.Run(ctx, "nft", "list", "table", "inet", n.opt.Table)
	switch {
	case err != nil && !isNotFound(err):
		return fmt.Errorf("nft list table inet %s: %w", n.opt.Table, err)
	case err != nil:
		if _, err := n.opt.Runner.RunInput(ctx, n.script(false), "nft", "-f", "-"); err != nil {
			return fmt.Errorf("creating the firewall table: %w", err)
		}
		n.log.Info("firewall ready", "table", "inet "+n.opt.Table, "created", true)
	case n.shapeOK(string(listing)):
		n.log.Info("firewall ready", "table", "inet "+n.opt.Table, "created", false,
			"note", "the existing table has the right shape; its blocks are kept")
	default:
		n.log.Warn("the firewall table does not have the expected shape; replacing it", "table", "inet "+n.opt.Table)
		if _, err := n.opt.Runner.RunInput(ctx, n.script(true), "nft", "-f", "-"); err != nil {
			return fmt.Errorf("replacing the firewall table: %w", err)
		}
	}

	n.mu.Lock()
	n.ready = true
	n.mu.Unlock()
	return nil
}

// Ready reports whether Ensure has succeeded.
func (n *Nftables) Ready() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ready
}

// Ban blocks an address until the decision expires, and makes the firewall's
// timeout match the decision.
//
// Adding an element that already exists does not change its timeout, so a
// renewed ban would expire at the old time. An existing element is therefore
// replaced — deleted and added again in one transaction, so the address is
// never unblocked in between. Adding a missing element is a plain add.
func (n *Nftables) Ban(ctx context.Context, d Decision) error {
	set, err := n.setFor(d.IP)
	if err != nil {
		return err
	}
	elem := d.IP
	if !d.Permanent() {
		ttl := time.Until(d.Until)
		if ttl <= 0 {
			return fmt.Errorf("ban for %s has already expired", d.IP)
		}
		secs := int(ttl.Seconds())
		if secs < 1 {
			secs = 1
		}
		elem = fmt.Sprintf("%s timeout %ds", d.IP, secs)
	}
	add := []string{"add", "element", "inet", n.opt.Table, set, "{ " + elem + " }"}
	if n.opt.DryRun {
		n.log.Info("dry run: would block", "ip", d.IP, "command", "nft "+strings.Join(add, " "))
		return nil
	}
	present := false
	if cur, err := n.List(ctx); err == nil {
		for _, c := range cur {
			if c.IP == d.IP {
				present = true
			}
		}
	}
	if present {
		script := fmt.Sprintf("delete element inet %s %s { %s }\n%s\n", n.opt.Table, set, d.IP, strings.Join(add, " "))
		if _, err := n.opt.Runner.RunInput(ctx, script, "nft", "-f", "-"); err == nil {
			n.log.Info("address block renewed", "ip", d.IP, "until", untilString(d.Until), "reason", d.Reason)
			return nil
		}
		// The element may have expired between listing and replacing; a plain
		// add is right in that case, and harmless in the others.
	}
	if _, err := n.opt.Runner.Run(ctx, "nft", add...); err != nil {
		return fmt.Errorf("blocking %s: %w", d.IP, err)
	}
	n.log.Info("address blocked", "ip", d.IP, "until", untilString(d.Until), "reason", d.Reason)
	return nil
}

// Unban removes a block. A missing element is success: the caller asked for the
// address not to be blocked, and it is not.
func (n *Nftables) Unban(ctx context.Context, ip string) error {
	set, err := n.setFor(ip)
	if err != nil {
		return err
	}
	args := []string{"delete", "element", "inet", n.opt.Table, set, "{ " + ip + " }"}
	if n.opt.DryRun {
		n.log.Info("dry run: would unblock", "ip", ip, "command", "nft "+strings.Join(args, " "))
		return nil
	}
	if _, err := n.opt.Runner.Run(ctx, "nft", args...); err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("unblocking %s: %w", ip, err)
	}
	n.log.Info("address unblocked", "ip", ip)
	return nil
}

// List returns the addresses currently blocked, as the firewall sees them.
// This is what makes it possible to tell the store's intent from the host's
// actual state.
func (n *Nftables) List(ctx context.Context) ([]Decision, error) {
	var out []Decision
	for _, set := range []string{n.opt.Set4, n.opt.Set6} {
		raw, err := n.opt.Runner.Run(ctx, "nft", "list", "set", "inet", n.opt.Table, set)
		if err != nil {
			if isNotFound(err) {
				continue
			}
			return out, fmt.Errorf("listing %s: %w", set, err)
		}
		out = append(out, parseElements(string(raw))...)
	}
	return out, nil
}

// Teardown removes the agent's table, which is how uninstalling leaves no
// trace in the firewall.
func (n *Nftables) Teardown(ctx context.Context) error {
	if n.opt.DryRun {
		return nil
	}
	if _, err := n.opt.Runner.Run(ctx, "nft", "delete", "table", "inet", n.opt.Table); err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("removing the firewall table: %w", err)
	}
	return nil
}

func (n *Nftables) setFor(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("%q is not an IP address", ip)
	}
	if parsed.To4() != nil {
		return n.opt.Set4, nil
	}
	return n.opt.Set6, nil
}

// parseElements reads the addresses out of `nft list set` output, which looks
// like:
//
//	set blocked4 {
//	  type ipv4_addr
//	  flags timeout
//	  elements = { 198.51.100.7 timeout 1h expires 59m2s,
//	               203.0.113.9 }
//	}
func parseElements(s string) []Decision {
	i := strings.Index(s, "elements = {")
	if i < 0 {
		return nil
	}
	rest := s[i+len("elements = {"):]
	j := strings.IndexByte(rest, '}')
	if j < 0 {
		return nil
	}
	var out []Decision
	for _, part := range strings.Split(rest[:j], ",") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		if net.ParseIP(fields[0]) == nil {
			continue
		}
		d := Decision{IP: fields[0]}
		// "expires 59m2s" is what is left of the timeout, which is the only
		// part worth reporting: the original duration is in the store.
		for k := 1; k+1 < len(fields); k++ {
			if fields[k] == "expires" {
				if ttl, ok := parseNftDuration(fields[k+1]); ok {
					d.Until = time.Now().Add(ttl)
				}
			}
		}
		out = append(out, d)
	}
	return out
}

// isNotFound recognizes nft complaining about something that is not there,
// which several operations treat as success.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "no such set") ||
		strings.Contains(msg, "not exist")
}

func untilString(t time.Time) string {
	if t.IsZero() {
		return "permanent"
	}
	return t.Format(time.RFC3339)
}

var nftDurationRe = regexp.MustCompile(`(\d+)(ms|w|d|h|m|s)`)

// parseNftDuration reads the durations `nft list set` prints: "59m2s",
// "29d23h59m1s", "1s130ms". Go's time.ParseDuration has no days or weeks, so a
// 30-day ban would otherwise read as permanent.
func parseNftDuration(s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	var total time.Duration
	rest := s
	for rest != "" {
		loc := nftDurationRe.FindStringSubmatchIndex(rest)
		if loc == nil || loc[0] != 0 {
			return 0, false
		}
		n, err := strconv.ParseInt(rest[loc[2]:loc[3]], 10, 64)
		if err != nil {
			return 0, false
		}
		unit := map[string]time.Duration{
			"ms": time.Millisecond, "s": time.Second, "m": time.Minute,
			"h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour,
		}[rest[loc[4]:loc[5]]]
		total += time.Duration(n) * unit
		rest = rest[loc[1]:]
	}
	return total, true
}
