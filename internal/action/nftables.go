package action

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
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
}

// ExecRunner runs commands for real.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return out, err
		}
		return out, fmt.Errorf("%s: %s", err, msg)
	}
	return out, nil
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

// Ensure creates the table, the two sets and the drop rules, replacing any
// previous copy. Recreating rather than patching keeps the firewall state
// exactly what the store says it should be: the store is the source of truth,
// and the agent re-applies the active bans after this call.
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

	// A missing table is the normal case on first start, so the error is
	// ignored rather than reported.
	_, _ = n.opt.Runner.Run(ctx, "nft", "delete", "table", "inet", n.opt.Table)

	steps := [][]string{
		{"add", "table", "inet", n.opt.Table},
		{"add", "set", "inet", n.opt.Table, n.opt.Set4, "{ type ipv4_addr; flags timeout, interval; }"},
		{"add", "set", "inet", n.opt.Table, n.opt.Set6, "{ type ipv6_addr; flags timeout, interval; }"},
		{"add", "chain", "inet", n.opt.Table, "input",
			fmt.Sprintf("{ type filter hook input priority %d; policy accept; }", nftPriority)},
		{"add", "rule", "inet", n.opt.Table, "input", "ip", "saddr", "@" + n.opt.Set4, "drop"},
		{"add", "rule", "inet", n.opt.Table, "input", "ip6", "saddr", "@" + n.opt.Set6, "drop"},
	}
	for _, args := range steps {
		if _, err := n.opt.Runner.Run(ctx, "nft", args...); err != nil {
			return fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
		}
	}

	n.mu.Lock()
	n.ready = true
	n.mu.Unlock()
	n.log.Info("firewall ready", "table", "inet "+n.opt.Table, "sets", n.opt.Set4+", "+n.opt.Set6)
	return nil
}

// Ready reports whether Ensure has succeeded.
func (n *Nftables) Ready() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ready
}

// Ban blocks an address until the decision expires. Adding an element that is
// already there is not an error for nftables, which makes this idempotent, as
// a banner must be: the same decision arrives again after a restart.
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
		elem = fmt.Sprintf("%s timeout %ds", d.IP, int(ttl.Seconds()))
	}
	args := []string{"add", "element", "inet", n.opt.Table, set, "{ " + elem + " }"}
	if n.opt.DryRun {
		n.log.Info("dry run: would block", "ip", d.IP, "command", "nft "+strings.Join(args, " "))
		return nil
	}
	if _, err := n.opt.Runner.Run(ctx, "nft", args...); err != nil {
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
				if ttl, err := time.ParseDuration(fields[k+1]); err == nil {
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
