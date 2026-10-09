package action

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner records what would have been run and can be told to fail.
type fakeRunner struct {
	mu   sync.Mutex
	cmds []string
	out  map[string]string // first matching substring wins
	fail map[string]error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{out: map[string]string{}, fail: map[string]error{}}
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.cmds = append(f.cmds, line)
	f.mu.Unlock()
	for pat, err := range f.fail {
		if strings.Contains(line, pat) {
			return nil, err
		}
	}
	for pat, out := range f.out {
		if strings.Contains(line, pat) {
			return []byte(out), nil
		}
	}
	return nil, nil
}

func (f *fakeRunner) ran(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func (f *fakeRunner) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func TestNftablesEnsureBuildsItsOwnTable(t *testing.T) {
	r := newFakeRunner()
	n := NewNftables(NftablesOptions{Runner: r})
	if err := n.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !n.Ready() {
		t.Error("Ready should be true after Ensure")
	}

	want := []string{
		"nft --version",
		"add table inet auditdsec",
		"add set inet auditdsec blocked4",
		"add set inet auditdsec blocked6",
		"add chain inet auditdsec input",
		"ip saddr @blocked4 drop",
		"ip6 saddr @blocked6 drop",
	}
	for _, w := range want {
		if !r.ran(w) {
			t.Errorf("missing step %q; ran:\n%s", w, strings.Join(r.all(), "\n"))
		}
	}
	// Everything must live in the agent's own table: the host's firewall is
	// not ours to edit.
	for _, c := range r.all() {
		if strings.Contains(c, "filter") && !strings.Contains(c, "auditdsec") {
			t.Errorf("command touches a table that is not ours: %q", c)
		}
	}
}

// Recreating the table makes the store the single source of truth, instead of
// leaving stale rules from a previous run behind.
func TestNftablesEnsureReplacesAnOldTable(t *testing.T) {
	r := newFakeRunner()
	if err := NewNftables(NftablesOptions{Runner: r}).Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.ran("delete table inet auditdsec") {
		t.Error("Ensure should drop a previous copy of the table first")
	}
}

func TestNftablesEnsureReportsAMissingNft(t *testing.T) {
	r := newFakeRunner()
	r.fail["--version"] = errors.New("executable file not found in $PATH")
	err := NewNftables(NftablesOptions{Runner: r}).Ensure(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	// The message has to tell the operator what to do about it.
	for _, want := range []string{"nftables", "ban.backend"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}

func TestNftablesBanWithTimeout(t *testing.T) {
	r := newFakeRunner()
	n := NewNftables(NftablesOptions{Runner: r})
	until := time.Now().Add(time.Hour)
	if err := n.Ban(context.Background(), Decision{IP: "198.51.100.7", Until: until}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("add element inet auditdsec blocked4") {
		t.Errorf("ran:\n%s", strings.Join(r.all(), "\n"))
	}
	if !r.ran("timeout 35") && !r.ran("timeout 36") {
		t.Errorf("the ban should carry a timeout of about an hour:\n%s", strings.Join(r.all(), "\n"))
	}
}

// A permanent ban must not carry a timeout, or the firewall would quietly
// forget it.
func TestNftablesBanPermanent(t *testing.T) {
	r := newFakeRunner()
	n := NewNftables(NftablesOptions{Runner: r})
	if err := n.Ban(context.Background(), Decision{IP: "198.51.100.7"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.all() {
		if strings.Contains(c, "timeout") {
			t.Errorf("a permanent ban should have no timeout: %q", c)
		}
	}
}

func TestNftablesBanIPv6UsesTheOtherSet(t *testing.T) {
	r := newFakeRunner()
	n := NewNftables(NftablesOptions{Runner: r})
	if err := n.Ban(context.Background(), Decision{IP: "2001:db8::1", Until: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("blocked6") {
		t.Errorf("an IPv6 address belongs in the v6 set:\n%s", strings.Join(r.all(), "\n"))
	}
}

func TestNftablesRejectsNonsense(t *testing.T) {
	n := NewNftables(NftablesOptions{Runner: newFakeRunner()})
	if err := n.Ban(context.Background(), Decision{IP: "not-an-ip", Until: time.Now().Add(time.Hour)}); err == nil {
		t.Error("expected an error for a bad address")
	}
	if err := n.Ban(context.Background(), Decision{IP: "1.2.3.4", Until: time.Now().Add(-time.Hour)}); err == nil {
		t.Error("expected an error for a ban that has already expired")
	}
}

// Unbanning something that is not blocked is what the caller wanted anyway.
func TestNftablesUnbanIsForgiving(t *testing.T) {
	r := newFakeRunner()
	r.fail["delete element"] = errors.New("Error: Could not process rule: No such file or directory")
	n := NewNftables(NftablesOptions{Runner: r})
	if err := n.Unban(context.Background(), "198.51.100.7"); err != nil {
		t.Errorf("a missing element should not be an error: %v", err)
	}
}

func TestNftablesUnbanReportsRealFailures(t *testing.T) {
	r := newFakeRunner()
	r.fail["delete element"] = errors.New("Error: Operation not permitted")
	n := NewNftables(NftablesOptions{Runner: r})
	if err := n.Unban(context.Background(), "198.51.100.7"); err == nil {
		t.Error("a permission problem must be reported")
	}
}

func TestNftablesList(t *testing.T) {
	r := newFakeRunner()
	r.out["list set inet auditdsec blocked4"] = `table inet auditdsec {
  set blocked4 {
    type ipv4_addr
    flags timeout
    elements = { 198.51.100.7 timeout 1h expires 59m2s,
                 203.0.113.9 }
  }
}`
	r.out["list set inet auditdsec blocked6"] = `table inet auditdsec {
  set blocked6 {
    type ipv6_addr
    elements = { 2001:db8::1 }
  }
}`
	got, err := NewNftables(NftablesOptions{Runner: r}).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d decisions, want 3: %+v", len(got), got)
	}
	byIP := map[string]Decision{}
	for _, d := range got {
		byIP[d.IP] = d
	}
	if d, ok := byIP["198.51.100.7"]; !ok || d.Permanent() {
		t.Errorf("the timed ban was misread: %+v", d)
	}
	if d, ok := byIP["203.0.113.9"]; !ok || !d.Permanent() {
		t.Errorf("an element with no timeout is permanent: %+v", d)
	}
	if _, ok := byIP["2001:db8::1"]; !ok {
		t.Error("the v6 set was not read")
	}
}

func TestNftablesListWithNoTable(t *testing.T) {
	r := newFakeRunner()
	r.fail["list set"] = errors.New("Error: No such file or directory")
	got, err := NewNftables(NftablesOptions{Runner: r}).List(context.Background())
	if err != nil {
		t.Fatalf("a missing table should read as empty, not fail: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}

// Dry run exists because the failure mode of this feature is locking the owner
// out of their own server.
func TestNftablesDryRunChangesNothing(t *testing.T) {
	r := newFakeRunner()
	n := NewNftables(NftablesOptions{Runner: r, DryRun: true})
	if err := n.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := n.Ban(context.Background(), Decision{IP: "198.51.100.7", Until: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := n.Unban(context.Background(), "198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.all() {
		if strings.Contains(c, "add element") || strings.Contains(c, "delete element") ||
			strings.Contains(c, "add table") || strings.Contains(c, "add rule") {
			t.Errorf("dry run executed a state-changing command: %q", c)
		}
	}
	if !strings.Contains(n.Name(), "dry run") {
		t.Errorf("Name should say so: %q", n.Name())
	}
}

func TestNftablesTeardown(t *testing.T) {
	r := newFakeRunner()
	if err := NewNftables(NftablesOptions{Runner: r}).Teardown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.ran("delete table inet auditdsec") {
		t.Error("Teardown should remove the table")
	}
}

func TestNoopBannerSatisfiesTheInterface(t *testing.T) {
	var b Banner = NoopBanner{}
	ctx := context.Background()
	if err := b.Ban(ctx, Decision{IP: "1.2.3.4"}); err != nil {
		t.Error(err)
	}
	if err := b.Unban(ctx, "1.2.3.4"); err != nil {
		t.Error(err)
	}
	if list, err := b.List(ctx); err != nil || len(list) != 0 {
		t.Errorf("List = %v, %v", list, err)
	}
	if b.Name() == "" {
		t.Error("a banner needs a name")
	}
}

func TestIsNotFound(t *testing.T) {
	if !isNotFound(errors.New("Error: Could not process rule: No such file or directory")) {
		t.Error("nft's missing-object error should be recognized")
	}
	if isNotFound(errors.New("Operation not permitted")) {
		t.Error("a permission error is not a missing object")
	}
	if isNotFound(nil) {
		t.Error("nil is not an error")
	}
}

var _ Banner = (*Nftables)(nil)
